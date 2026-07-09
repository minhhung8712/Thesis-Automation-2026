#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================
 forwarder.py  —  CẦU NỐI SYSLOG (pfSense) → WEBHOOK (n8n)   [BẢN HOÀN CHỈNH]
========================================================================

VAI TRÒ:
  pfSense (192.168.10.1) "nói" bằng syslog UDP (text thô). n8n "nghe" bằng
  HTTP JSON. File này đứng giữa, làm 3 việc: NGHE → DỊCH → LỌC & GỬI.
  Chạy trên chính VM n8n (192.168.10.2).

CƠ CHẾ PHÂN LOẠI (parse_line xét theo thứ tự ưu tiên):
  (1) Suricata alert  → đọc tên rule, phân biệt BRUTE_FORCE/PORT_SCAN/IDS_ALERT
  (2) VPN down        → VPN_TUNNEL_DOWN
  (3) DHCP mới        → NEW_MAC
  (4) Filterlog block → đoán theo PORT ĐÍCH: port 22/3389... = BRUTE_FORCE,
                        còn lại = PORT_SCAN
  (5) Không khớp      → UNKNOWN (chỉ khi DEBUG) hoặc bỏ qua

LƯU Ý: filterlog KHÔNG chứa tên loại tấn công, nên (4) chỉ là "đoán theo
  port". Muốn phân loại CHÍNH XÁC (đọc nội dung) thì phải bật Suricata (1).
========================================================================
"""

import socket
import json
import re
import logging
import urllib.request
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 1 — CẤU HÌNH                                                 ║
# ╚══════════════════════════════════════════════════════════════════╝

LISTEN_IP   = "0.0.0.0"        # nghe trên mọi card mạng CỦA MÁY N8N (không phải IP pfSense)
LISTEN_PORT = 514             # khớp port pfSense gửi (192.168.10.2:514)
N8N_WEBHOOK = "http://127.0.0.1:5678/webhook/pfsense-event"
SITE        = "HCM-01"

PFSENSE_IP  = "192.168.10.1"
ONLY_ACCEPT_FROM_PFSENSE = False   # True = chỉ nhận gói từ pfSense (production)
DEBUG_FORWARD_ALL        = False   # True = forward cả log nền (UNKNOWN) để debug

# Dải mạng NỘI BỘ — IP thuộc các dải này KHÔNG bị coi là attacker
INTERNAL_NETS = ["192.168.10.", "192.168.11.", "192.168.12.", "192.168.20."]

# IP hạ tầng / noise — bỏ qua theo TIỀN TỐ (prefix)
IGNORE_PREFIXES = [
    "169.254.",       # link-local (Windows tự sinh)
    "224.", "239.",   # multicast
    "255.",           # broadcast
    "0.",             # invalid
    "127.",           # loopback
]

# IP cụ thể bỏ qua — so khớp CHÍNH XÁC (tránh nhầm 192.168.183.1 với .133)
IGNORE_EXACT = [
    "192.168.183.1",  # gateway WAN (KHÔNG phải attacker)
    "192.168.10.1",   # pfSense LAN
]

# Các cổng dịch vụ thường bị BRUTE FORCE (đăng nhập)
BRUTE_PORTS = {22: "SSH", 3389: "RDP", 21: "FTP", 23: "Telnet",
               3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL"}

# File log xoay vòng
LOG_FILE      = "forwarded_events.log"
LOG_MAX_BYTES = 10 * 1024 * 1024   # 10 MB mỗi file
LOG_BACKUP    = 5                  # giữ 5 file gần nhất


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 2 — BỘ GHI LOG RA FILE (rotating)                            ║
# ╚══════════════════════════════════════════════════════════════════╝

logger = logging.getLogger("forwarder")
logger.setLevel(logging.INFO)
_fh = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES,
                          backupCount=LOG_BACKUP, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger.addHandler(_fh)


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 3 — REGEX                                                    ║
# ╚══════════════════════════════════════════════════════════════════╝

# Suricata fast.log
RE_PRIORITY = re.compile(r"\[Priority:\s*(\d+)\]")
RE_MSG      = re.compile(r"\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]")
RE_CLASS    = re.compile(r"\[Classification:\s*(.*?)\]")
RE_FLOW     = re.compile(r"\{(\w+)\}\s+([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)")

# Tiện ích
RE_ANY_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
RE_MAC    = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")

# Filterlog: ...,src_ip,dst_ip,sport,dport,...  -> lấy 2 IP + 2 port liền nhau
RE_FILTERLOG_PORTS = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}),(\d{1,3}(?:\.\d{1,3}){3}),(\d+),(\d+)")


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 4 — HÀM PHỤ TRỢ                                              ║
# ╚══════════════════════════════════════════════════════════════════╝

def severity_from_priority(prio: str) -> str:
    return {"1": "HIGH", "2": "MEDIUM", "3": "LOW"}.get(prio, "MEDIUM")


def is_internal(ip: str) -> bool:
    """IP thuộc mạng nội bộ (không coi là attacker)."""
    return bool(ip) and any(ip.startswith(net) for net in INTERNAL_NETS)


def should_ignore(ip: str) -> bool:
    """IP hạ tầng / noise -> luôn bỏ qua."""
    if not ip:
        return True
    if ip in IGNORE_EXACT:                                   # khớp chính xác
        return True
    return any(ip.startswith(p) for p in IGNORE_PREFIXES)   # khớp tiền tố


def pick_attacker(src: str, dst: str):
    """Chọn IP KHÔNG thuộc nội bộ làm attacker."""
    if src and not is_internal(src):
        return src
    if dst and not is_internal(dst):
        return dst
    return src or dst


def classify_suricata(msg: str, classification: str) -> str:
    """Đọc tên rule + phân loại của Suricata -> event_type. (Chính xác nhất)"""
    text = (msg + " " + classification).lower()
    if "brute" in text or "ssh scan" in text or "login" in text:
        return "BRUTE_FORCE"
    if "scan" in text or "information leak" in text:
        return "PORT_SCAN"
    if "dos" in text or "flood" in text:
        return "HIGH_BANDWIDTH"
    return "IDS_ALERT"


def parse_filterlog(raw: str):
    """
    Parse log FIREWALL (filterlog) khi pfSense CHẶN gói.
    filterlog KHÔNG có tên tấn công, nên ĐOÁN theo PORT ĐÍCH:
      - port 22/3389/21... (dịch vụ login) -> BRUTE_FORCE
      - port khác / nhiều port             -> PORT_SCAN
    """
    if "filterlog" not in raw:
        return None
    if ",block," not in raw and ",block" not in raw:   # chỉ quan tâm gói bị CHẶN
        return None

    ips = RE_ANY_IP.findall(raw)
    if len(ips) < 2:
        return None
    src, dst = ips[0], ips[1]
    attacker = pick_attacker(src, dst)

    # Bỏ qua nếu attacker là nội bộ hoặc noise hạ tầng
    if is_internal(attacker) or should_ignore(attacker):
        return None

    # Lấy port đích để đoán loại tấn công
    dport = None
    m = RE_FILTERLOG_PORTS.search(raw)
    if m:
        try:
            dport = int(m.group(4))
        except ValueError:
            dport = None

    if dport in BRUTE_PORTS:
        event_type = "BRUTE_FORCE"
        severity   = "HIGH"
        message    = f"firewall block - nghi brute force {BRUTE_PORTS[dport]} (port {dport})"
    else:
        event_type = "PORT_SCAN"
        severity   = "MEDIUM"
        message    = f"firewall block - nghi port scan (port {dport})"

    return {
        "event_type": event_type,
        "src_ip": attacker,
        "dst_ip": dst if attacker == src else src,
        "dst_port": dport,
        "protocol": "tcp" if ",tcp," in raw.lower() else None,
        "severity": severity,
        "message": message,
        "detector": "filterlog",
    }


def parse_line(raw: str):
    """Nhận 1 dòng syslog thô, trả về dict đã chuẩn hóa hoặc None."""
    low = raw.lower()

    # (1) Suricata alert — ưu tiên cao nhất (đã phân tích sẵn, chính xác)
    if "[**]" in raw and RE_FLOW.search(raw):
        flow = RE_FLOW.search(raw)
        prio = RE_PRIORITY.search(raw).group(1) if RE_PRIORITY.search(raw) else "2"
        msg  = RE_MSG.search(raw).group(1) if RE_MSG.search(raw) else ""
        clz  = RE_CLASS.search(raw).group(1) if RE_CLASS.search(raw) else ""
        src, dst = flow.group(2), flow.group(4)
        attacker = pick_attacker(src, dst)
        if should_ignore(attacker):
            return None
        return {
            "event_type": classify_suricata(msg, clz),
            "src_ip": attacker,
            "dst_ip": dst,
            "dst_port": int(flow.group(5)) if flow.group(5).isdigit() else None,
            "protocol": flow.group(1),
            "severity": severity_from_priority(prio),
            "message": msg,
            "detector": "suricata",
        }

    # (2) VPN tunnel down
    if ("openvpn" in low or "charon" in low or "ipsec" in low) and \
       any(k in low for k in ("down", "disconnect", "deleting", "tunnel closed", "link inactive")):
        ips = RE_ANY_IP.findall(raw)
        return {
            "event_type": "VPN_TUNNEL_DOWN",
            "src_ip": ips[0] if ips else None,
            "dst_ip": None, "protocol": "VPN", "severity": "HIGH",
            "message": raw[-200:], "detector": "vpn",
        }

    # (3) Thiết bị mới (DHCP)
    if "dhcp" in low and ("dhcpack" in low or "new lease" in low) and RE_MAC.search(raw):
        ips = RE_ANY_IP.findall(raw)
        return {
            "event_type": "NEW_MAC",
            "src_ip": ips[0] if ips else None,
            "dst_ip": None, "protocol": "DHCP", "severity": "LOW",
            "message": RE_MAC.search(raw).group(1), "detector": "dhcp",
        }

    # (4) Firewall block (filterlog) — đoán theo port đích
    fw = parse_filterlog(raw)
    if fw:
        return fw

    # (5) Không nhận diện — chỉ forward khi bật DEBUG
    if DEBUG_FORWARD_ALL:
        ip = (RE_ANY_IP.findall(raw) or [None])[0]
        return {
            "event_type": "UNKNOWN",
            "src_ip": ip,
            "dst_ip": None, "protocol": None, "severity": "LOW",
            "message": raw[-200:], "detector": "debug",
        }
    return None


def post_to_n8n(payload: dict):
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


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 5 — VÒNG LẶP CHÍNH: NHẬN TÍN HIỆU TỪ pfSense                ║
# ╚══════════════════════════════════════════════════════════════════╝

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # UDP
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[forwarder] nghe syslog UDP {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[forwarder] chi nhan tu pfSense? {ONLY_ACCEPT_FROM_PFSENSE} (pfSense={PFSENSE_IP})")
    print(f"[forwarder] DEBUG_FORWARD_ALL = {DEBUG_FORWARD_ALL}")
    print(f"[forwarder] forward toi {N8N_WEBHOOK}")
    print(f"[forwarder] ghi log vao {LOG_FILE} ({LOG_BACKUP}x{LOG_MAX_BYTES//1024//1024}MB)\n")

    while True:
        # >>> DÒNG NHẬN TÍN HIỆU: recvfrom trả về (nội dung, (IP_gửi, port)) <<<
        data, addr = sock.recvfrom(8192)
        sender_ip = addr[0]           # = 192.168.10.1 khi pfSense gửi

        if ONLY_ACCEPT_FROM_PFSENSE and sender_ip != PFSENSE_IP:
            continue                  # bỏ gói không phải từ pfSense

        raw = data.decode("utf-8", errors="replace").strip()
        parsed = parse_line(raw)
        if not parsed:
            continue                  # log nền / noise -> bỏ qua

        parsed.update({
            "event_id": f"evt-{int(datetime.now().timestamp()*1000)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "site": SITE,
            "source_host": sender_ip,
        })

        print(f"[{datetime.now().strftime('%H:%M:%S')}] tu {sender_ip} -> "
              f"{parsed['event_type']} (src={parsed.get('src_ip')}, "
              f"port={parsed.get('dst_port')}, by={parsed.get('detector')})")

        status = post_to_n8n(parsed)
        logger.info(json.dumps({**parsed, "n8n_status": status}, ensure_ascii=False))


if __name__ == "__main__":
    main()
