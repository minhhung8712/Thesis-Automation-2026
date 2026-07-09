#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================
 forwarder.py — CẦU NỐI SYSLOG (pfSense) → n8n   [BẢN NGƯỠNG / THRESHOLD]
========================================================================

VAI TRÒ:
  Chạy trên VM n8n (192.168.10.2). Đứng giữa pfSense và n8n, làm 3 việc:
  NGHE syslog UDP từ pfSense → PHÁT HIỆN tấn công theo ngưỡng → GỬI n8n.

KHÁC BIỆT CỐT LÕI so với bản cũ:
  Bản cũ nhìn 1 DÒNG log đơn lẻ rồi ĐOÁN loại tấn công theo port (nông,
  nhiều lỗ hổng). Bản này TÍCH LŨY sự kiện theo IP nguồn trong một CỬA SỔ
  THỜI GIAN TRƯỢT (sliding window), rồi phân loại theo ĐẶC TRƯNG HÀNH VI
  thật của từng loại tấn công:

    BRUTE_FORCE : 1 IP thử sai đăng nhập >= 5 lần vào CÙNG 1 port / 60 giây
                  (nguồn tốt nhất: Auth log "Failed password" - bằng chứng trực tiếp)
    PORT_SCAN   : 1 IP chạm >= 15 port KHÁC NHAU / 10 giây
                  (nguồn: firewall filterlog)
    CONN_FLOOD  : 1 IP tạo >= 100 sự kiện / 10 giây  (tấn công DoS)
                  (nguồn: firewall filterlog)

  Chỉ gửi n8n 1 EVENT PHÁT HIỆN khi vượt ngưỡng (kèm COOLDOWN chống spam),
  thay vì gửi mỗi dòng log. Sự kiện tức thời (VPN down / thiết bị mới /
  alert Suricata) thì gửi ngay, không cần đếm ngưỡng.
========================================================================
"""

import socket                    # tạo "ổ cắm" UDP để nghe syslog
import json                      # đóng gói dữ liệu JSON
import re                        # regex bóc tách text
import time                      # lấy thời gian cho cửa sổ trượt
import logging                   # ghi log ra file
import urllib.request            # gửi HTTP POST (không cần cài 'requests')
from collections import defaultdict, deque   # cấu trúc lưu bộ đếm theo IP
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 1 — CẤU HÌNH                                                 ║
# ╚══════════════════════════════════════════════════════════════════╝

LISTEN_IP   = "0.0.0.0"        # nghe trên MỌI card mạng CỦA MÁY N8N (không phải IP pfSense)
LISTEN_PORT = 514             # khớp port pfSense gửi tới (192.168.10.2:514)
N8N_WEBHOOK = "http://127.0.0.1:5678/webhook/pfsense-event"   # webhook WF-00
SITE        = "HCM-01"        # tên site, gắn vào mỗi event

PFSENSE_IP  = "192.168.10.1"
ONLY_ACCEPT_FROM_PFSENSE = False   # True = chỉ nhận gói từ pfSense (bảo mật, production)
DEBUG_FORWARD_ALL        = False   # True = forward cả log nền (UNKNOWN) để debug

# Dải mạng NỘI BỘ — IP thuộc đây KHÔNG bao giờ bị coi là attacker (chống tự block)
INTERNAL_NETS = ["192.168.10.", "192.168.11.", "192.168.12.", "192.168.20."]

# IP hạ tầng / noise — bỏ qua theo TIỀN TỐ (mọi IP bắt đầu bằng các chuỗi này)
IGNORE_PREFIXES = ["169.254.", "224.", "239.", "255.", "0.", "127."]

# IP bỏ qua theo KHỚP CHÍNH XÁC (tách riêng để tránh 192.168.183.1 khớp nhầm
# 192.168.183.133 — vì .133 cũng bắt đầu bằng "192.168.183.1")
IGNORE_EXACT = ["192.168.183.1", "192.168.10.1"]

# ----- NGƯỠNG PHÁT HIỆN (có căn cứ, chỉnh được) -----
#   count / distinct_ports : số lượng cần đạt để kích hoạt cảnh báo
#   window                 : cửa sổ thời gian tính (giây)
# CĂN CỨ CHỌN NGƯỠNG:
#   BRUTE_FORCE: theo chuẩn fail2ban (5 lần/khoảng). Người dùng thật hiếm khi
#                gõ sai 5 lần/phút; công cụ hydra gõ sai hàng chục lần mỗi giây.
#   PORT_SCAN  : người dùng thật chỉ kết nối vài port; nmap chạm hàng trăm port/giây,
#                nên 15 port khác nhau trong 10s là dấu hiệu quét rõ ràng.
#   CONN_FLOOD : 100 sự kiện/10s từ 1 host vượt xa lưu lượng bình thường -> nghi DoS.
THRESHOLDS = {
    "BRUTE_FORCE": {"count": 5,           "window": 60},   # 5 lần fail / 60s (cùng 1 port)
    "PORT_SCAN":   {"distinct_ports": 15, "window": 10},   # 15 port khác nhau / 10s
    "CONN_FLOOD":  {"count": 100,         "window": 10},   # 100 sự kiện / 10s
}

COOLDOWN        = 300    # giây: sau khi báo 1 IP+loại, KHÔNG báo lại trong 5 phút (chống spam)
MAX_TRACKED_IPS = 5000   # giới hạn số IP theo dõi cùng lúc (chống phình bộ nhớ)

# Cổng dịch vụ đăng nhập (chỉ để chú thích cho dễ đọc, KHÔNG dùng để đoán loại nữa)
LOGIN_PORTS = {22: "SSH", 3389: "RDP", 21: "FTP", 23: "Telnet",
               3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL"}

# Cấu hình file log xoay vòng
LOG_FILE      = "forwarded_events.log"
LOG_MAX_BYTES = 10 * 1024 * 1024   # mỗi file tối đa 10 MB
LOG_BACKUP    = 5                  # giữ 5 file cũ (trần 60 MB)


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 2 — BỘ GHI LOG RA FILE (rotating)                            ║
# ║ Lưu mỗi event đã gửi để backup + điều tra (forensics).           ║
# ╚══════════════════════════════════════════════════════════════════╝

logger = logging.getLogger("forwarder")
logger.setLevel(logging.INFO)
_fh = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES,
                          backupCount=LOG_BACKUP, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger.addHandler(_fh)


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 3 — CÁC MẪU REGEX ĐỂ BÓC TÁCH DÒNG SYSLOG                    ║
# ╚══════════════════════════════════════════════════════════════════╝

# --- Suricata fast.log (IDS) ---
RE_PRIORITY = re.compile(r"\[Priority:\s*(\d+)\]")            # bóc [Priority: 1]
RE_MSG      = re.compile(r"\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]")   # tên rule
RE_CLASS    = re.compile(r"\[Classification:\s*(.*?)\]")     # phân loại
RE_FLOW     = re.compile(r"\{(\w+)\}\s+([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)")
#   ^ bóc: {TCP} src_ip:src_port -> dst_ip:dst_port

# --- Tiện ích ---
RE_ANY_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")     # bắt mọi IPv4
RE_MAC    = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")  # bắt MAC

# --- Filterlog (firewall): ...,src_ip,dst_ip,sport,dport,... ---
RE_FILTERLOG_PORTS = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}),(\d{1,3}(?:\.\d{1,3}){3}),(\d+),(\d+)")

# --- Auth log (sshd) — BẰNG CHỨNG TRỰC TIẾP cho brute force ---
#   "Failed password for admin from 192.168.183.133 port 36808 ssh2"
#   "Failed password for invalid user root from 1.2.3.4 port 5 ssh2"
RE_SSH_FAIL    = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)")
#   "Invalid user oracle from 1.2.3.4"
RE_SSH_INVALID = re.compile(r"Invalid user (\S+) from ([\d.]+)")


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 4 — HÀM PHỤ TRỢ                                              ║
# ╚══════════════════════════════════════════════════════════════════╝

def severity_from_priority(prio: str) -> str:
    """Suricata Priority 1/2/3 -> mức độ HIGH/MEDIUM/LOW."""
    return {"1": "HIGH", "2": "MEDIUM", "3": "LOW"}.get(prio, "MEDIUM")


def is_internal(ip: str) -> bool:
    """IP thuộc mạng nội bộ? (không coi là attacker)."""
    return bool(ip) and any(ip.startswith(net) for net in INTERNAL_NETS)


def should_ignore(ip: str) -> bool:
    """IP hạ tầng / noise -> luôn bỏ qua (khớp cả EXACT lẫn PREFIX)."""
    if not ip:
        return True
    if ip in IGNORE_EXACT:                                   # khớp chính xác
        return True
    return any(ip.startswith(p) for p in IGNORE_PREFIXES)   # khớp tiền tố


def pick_attacker(src: str, dst: str):
    """Trong 2 IP của 1 gói, chọn IP KHÔNG thuộc nội bộ làm attacker."""
    if src and not is_internal(src):
        return src
    if dst and not is_internal(dst):
        return dst
    return src or dst


def classify_suricata(msg: str, classification: str) -> str:
    """Đọc tên rule Suricata -> event_type. Đây là cách phân loại CHÍNH XÁC
    nhất vì Suricata đã phân tích nội dung và ghi rõ loại tấn công."""
    text = (msg + " " + classification).lower()
    if "brute" in text or "ssh scan" in text or "login" in text:
        return "BRUTE_FORCE"
    if "scan" in text or "information leak" in text:
        return "PORT_SCAN"
    if "dos" in text or "flood" in text:
        return "CONN_FLOOD"
    return "IDS_ALERT"


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 5 — ENGINE PHÁT HIỆN THEO NGƯỠNG (sliding window)           ║
# ║ Đây là phần cốt lõi mới: tích lũy sự kiện + xét ngưỡng.          ║
# ╚══════════════════════════════════════════════════════════════════╝

# _events: mỗi IP nguồn ánh xạ tới một hàng đợi (deque) các sự kiện gần đây.
#   Mỗi phần tử = (timestamp, dst_port, kind)
#   kind = 'auth_fail' (thử login sai) | 'fw_block' (gói bị firewall chặn)
_events = defaultdict(deque)

# _last_alert: nhớ lần cuối đã báo cho từng (IP, loại) -> phục vụ COOLDOWN
_last_alert = {}

_MAX_WINDOW = 60   # giữ tối đa 60 giây lịch sử mỗi IP (đủ cho mọi ngưỡng)


def _trim(dq, now):
    """Xóa các sự kiện cũ hơn cửa sổ tối đa (60s) khỏi hàng đợi."""
    cutoff = now - _MAX_WINDOW
    while dq and dq[0][0] < cutoff:
        dq.popleft()


def _count(dq, now, window, kind=None, port=None):
    """Đếm số sự kiện trong 'window' giây gần nhất.
    Có thể lọc thêm theo kind (loại) và port (đích)."""
    cutoff = now - window
    n = 0
    for ts, p, k in dq:
        if ts < cutoff:
            continue
        if kind and k != kind:
            continue
        if port is not None and p != port:
            continue
        n += 1
    return n


def _distinct_ports(dq, now, window, kind=None):
    """Đếm số PORT ĐÍCH KHÁC NHAU trong 'window' giây gần nhất.
    Dùng để phát hiện port scan (chạm nhiều port)."""
    cutoff = now - window
    ports = set()
    for ts, p, k in dq:
        if ts >= cutoff and (kind is None or k == kind) and p is not None:
            ports.add(p)
    return len(ports)


def record_and_detect(ip, dport, kind, now=None):
    """
    Ghi 1 tín hiệu thô vào tracker của IP, rồi XÉT NGƯỠNG.
    Trả về (event_type, metric) nếu vượt ngưỡng, ngược lại None.

    Thứ tự xét: BRUTE_FORCE -> CONN_FLOOD -> PORT_SCAN.
    """
    if now is None:
        now = time.time()

    # Chống phình bộ nhớ: nếu theo dõi quá nhiều IP, dọn các IP đã hết sự kiện
    if len(_events) > MAX_TRACKED_IPS:
        for k in list(_events.keys()):
            _trim(_events[k], now)
            if not _events[k]:
                del _events[k]

    dq = _events[ip]
    dq.append((now, dport, kind))   # thêm sự kiện mới
    _trim(dq, now)                   # dọn sự kiện quá cũ

    # (1) BRUTE_FORCE: nhiều lần 'auth_fail' vào CÙNG 1 port trong window
    if kind == "auth_fail":
        th = THRESHOLDS["BRUTE_FORCE"]
        cnt = _count(dq, now, th["window"], kind="auth_fail", port=dport)
        if cnt >= th["count"]:
            return ("BRUTE_FORCE", cnt)

    # (2) CONN_FLOOD (DoS): TỔNG sự kiện quá nhiều trong window
    thf = THRESHOLDS["CONN_FLOOD"]
    total = _count(dq, now, thf["window"])
    if total >= thf["count"]:
        return ("CONN_FLOOD", total)

    # (3) PORT_SCAN: chạm nhiều PORT KHÁC NHAU (dựa trên fw_block) trong window
    ths = THRESHOLDS["PORT_SCAN"]
    dp = _distinct_ports(dq, now, ths["window"], kind="fw_block")
    if dp >= ths["distinct_ports"]:
        return ("PORT_SCAN", dp)

    return None


def in_cooldown(ip, event_type, now=None):
    """True nếu vừa báo IP+loại này gần đây (đang trong thời gian nghỉ COOLDOWN).
    Nếu chưa báo (hoặc đã quá COOLDOWN) thì ghi lại mốc thời gian và trả False
    (nghĩa là: cho phép gửi)."""
    if now is None:
        now = time.time()
    key = (ip, event_type)
    last = _last_alert.get(key)
    if last is not None and (now - last) < COOLDOWN:
        return True                  # còn trong thời gian nghỉ -> chặn
    _last_alert[key] = now           # cập nhật mốc, cho phép gửi
    return False


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 6 — TRÍCH XUẤT TÍN HIỆU TỪ 1 DÒNG SYSLOG                     ║
# ║ Trả về một trong ba:                                             ║
# ║   ('instant', dict) -> event tức thời, GỬI NGAY (VPN/DHCP/Suricata)║
# ║   ('signal',  dict) -> tín hiệu thô, ĐƯA VÀO ENGINE NGƯỠNG        ║
# ║   None                -> bỏ qua (log nền / noise)                 ║
# ╚══════════════════════════════════════════════════════════════════╝

def extract_signal(raw: str):
    low = raw.lower()

    # (A) Suricata alert -> TỨC THỜI (vì Suricata đã tự đếm ngưỡng bên trong)
    if "[**]" in raw and RE_FLOW.search(raw):
        flow = RE_FLOW.search(raw)
        prio = RE_PRIORITY.search(raw).group(1) if RE_PRIORITY.search(raw) else "2"
        msg  = RE_MSG.search(raw).group(1) if RE_MSG.search(raw) else ""
        clz  = RE_CLASS.search(raw).group(1) if RE_CLASS.search(raw) else ""
        src, dst = flow.group(2), flow.group(4)
        attacker = pick_attacker(src, dst)
        if should_ignore(attacker):
            return None
        return ("instant", {
            "event_type": classify_suricata(msg, clz),
            "src_ip": attacker, "dst_ip": dst,
            "dst_port": int(flow.group(5)) if flow.group(5).isdigit() else None,
            "protocol": flow.group(1),
            "severity": severity_from_priority(prio),
            "message": msg, "detector": "suricata",
        })

    # (B) VPN tunnel down -> TỨC THỜI
    if ("openvpn" in low or "charon" in low or "ipsec" in low) and \
       any(k in low for k in ("down", "disconnect", "deleting", "tunnel closed", "link inactive")):
        ips = RE_ANY_IP.findall(raw)
        return ("instant", {
            "event_type": "VPN_TUNNEL_DOWN",
            "src_ip": ips[0] if ips else None, "dst_ip": None,
            "protocol": "VPN", "severity": "HIGH",
            "message": raw[-200:], "detector": "vpn",
        })

    # (C) DHCP thiết bị mới -> TỨC THỜI
    if "dhcp" in low and ("dhcpack" in low or "new lease" in low) and RE_MAC.search(raw):
        ips = RE_ANY_IP.findall(raw)
        return ("instant", {
            "event_type": "NEW_MAC",
            "src_ip": ips[0] if ips else None, "dst_ip": None,
            "protocol": "DHCP", "severity": "LOW",
            "message": RE_MAC.search(raw).group(1), "detector": "dhcp",
        })

    # (D) Auth log SSH thất bại -> TÍN HIỆU cho engine ngưỡng (brute force)
    m = RE_SSH_FAIL.search(raw) or RE_SSH_INVALID.search(raw)
    if m and ("failed password" in low or "invalid user" in low):
        groups = m.groups()           # FAIL: (user, ip, port) | INVALID: (user, ip)
        ip = groups[1]
        if should_ignore(ip) or is_internal(ip):
            return None
        # dst_port = 22 (SSH) vì đây là log dịch vụ SSH
        return ("signal", {"kind": "auth_fail", "src_ip": ip,
                           "dst_port": 22, "detector": "authlog"})

    # (E) Firewall block (filterlog) -> TÍN HIỆU cho engine ngưỡng (scan / flood)
    if "filterlog" in raw and "block" in low:
        ips = RE_ANY_IP.findall(raw)
        if len(ips) >= 2:
            src, dst = ips[0], ips[1]
            attacker = pick_attacker(src, dst)
            if is_internal(attacker) or should_ignore(attacker):
                return None
            dport = None
            mm = RE_FILTERLOG_PORTS.search(raw)
            if mm:
                try:
                    dport = int(mm.group(4))
                except ValueError:
                    dport = None
            return ("signal", {"kind": "fw_block", "src_ip": attacker,
                               "dst_ip": dst, "dst_port": dport,
                               "detector": "filterlog"})

    # (F) Debug: forward mọi thứ khác (chỉ khi bật DEBUG_FORWARD_ALL)
    if DEBUG_FORWARD_ALL:
        return ("instant", {
            "event_type": "UNKNOWN",
            "src_ip": (RE_ANY_IP.findall(raw) or [None])[0],
            "dst_ip": None, "protocol": None, "severity": "LOW",
            "message": raw[-200:], "detector": "debug",
        })
    return None


def build_detection_event(event_type, sig, metric):
    """Dựng event PHÁT HIỆN (đã vượt ngưỡng) để gửi n8n, kèm số liệu minh chứng."""
    th = THRESHOLDS.get(event_type, {})
    win = th.get("window", "?")
    sev = "HIGH" if event_type in ("BRUTE_FORCE", "CONN_FLOOD") else "MEDIUM"
    detail = {
        "BRUTE_FORCE": f"{metric} lan dang nhap sai trong {win}s",
        "PORT_SCAN":   f"cham {metric} port khac nhau trong {win}s",
        "CONN_FLOOD":  f"{metric} ket noi trong {win}s",
    }.get(event_type, f"metric={metric}")
    return {
        "event_type": event_type,
        "src_ip": sig["src_ip"],
        "dst_ip": sig.get("dst_ip"),
        "dst_port": sig.get("dst_port"),
        "severity": sev,
        "metric": metric,           # con số thực tế đo được (vd 5 lần, 15 port)
        "threshold": th,            # ngưỡng đã dùng (để n8n/audit đối chiếu)
        "message": f"Nguong vuot: {detail}",
        "detector": sig.get("detector"),
    }


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 7 — GỬI n8n + GHI LOG                                        ║
# ╚══════════════════════════════════════════════════════════════════╝

def post_to_n8n(payload: dict):
    """Đóng gói dict thành JSON và POST sang webhook n8n."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        N8N_WEBHOOK, data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"  -> n8n {resp.status} | {payload['event_type']} | src={payload.get('src_ip')}")
            return resp.status
    except Exception as e:
        print(f"  !! POST that bai: {e}")
        return None


def emit(event: dict, sender_ip: str):
    """Gắn metadata, in ra màn hình, gửi n8n, ghi vào file log."""
    event.update({
        "event_id": f"evt-{int(time.time()*1000)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "site": SITE, "source_host": sender_ip,
    })
    print(f"[{datetime.now().strftime('%H:%M:%S')}] tu {sender_ip} -> "
          f"{event['event_type']} (src={event.get('src_ip')}, "
          f"port={event.get('dst_port')}, by={event.get('detector')}, "
          f"metric={event.get('metric','-')})")
    status = post_to_n8n(event)
    logger.info(json.dumps({**event, "n8n_status": status}, ensure_ascii=False))


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 8 — VÒNG LẶP CHÍNH: NHẬN TÍN HIỆU TỪ pfSense                ║
# ╚══════════════════════════════════════════════════════════════════╝

def main():
    # Mở ổ cắm UDP và gắn vào port 514 của máy n8n
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # SOCK_DGRAM = UDP
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[forwarder] nghe syslog UDP {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[forwarder] NGUONG brute={THRESHOLDS['BRUTE_FORCE']} "
          f"scan={THRESHOLDS['PORT_SCAN']} flood={THRESHOLDS['CONN_FLOOD']}")
    print(f"[forwarder] cooldown={COOLDOWN}s | forward toi {N8N_WEBHOOK}\n")

    while True:
        # >>> DÒNG NHẬN TÍN HIỆU: recvfrom trả về (nội dung, (IP_gửi, port)) <<<
        data, addr = sock.recvfrom(8192)
        sender_ip = addr[0]           # = 192.168.10.1 khi pfSense gửi

        if ONLY_ACCEPT_FROM_PFSENSE and sender_ip != PFSENSE_IP:
            continue                  # bỏ gói không phải từ pfSense

        raw = data.decode("utf-8", errors="replace").strip()

        # Trích xuất tín hiệu từ dòng syslog
        result = extract_signal(raw)
        if result is None:
            continue                  # log nền / noise -> bỏ qua

        mode, data_dict = result

        if mode == "instant":
            # Sự kiện tức thời -> gửi ngay
            emit(data_dict, sender_ip)

        elif mode == "signal":
            # Tín hiệu thô -> đưa vào engine ngưỡng
            hit = record_and_detect(data_dict["src_ip"],
                                    data_dict.get("dst_port"),
                                    data_dict["kind"])
            if hit:
                event_type, metric = hit
                # Chỉ gửi nếu KHÔNG đang trong thời gian nghỉ (chống spam)
                if not in_cooldown(data_dict["src_ip"], event_type):
                    emit(build_detection_event(event_type, data_dict, metric), sender_ip)


if __name__ == "__main__":
    main()
