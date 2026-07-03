#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================
 forwarder.py  —  CẦU NỐI SYSLOG (pfSense) → WEBHOOK (n8n)
========================================================================

VAI TRÒ TRONG HỆ THỐNG:
  pfSense (192.168.10.1) chỉ biết "nói" bằng giao thức SYSLOG (text thô,
  gửi qua UDP). n8n chỉ biết "nghe" bằng HTTP (JSON). Hai bên KHÔNG nói
  chuyện trực tiếp được. File này đứng GIỮA, làm 3 việc:

     1. NGHE  : mở 1 cổng UDP, chờ pfSense bắn gói syslog sang.
     2. DỊCH  : đọc dòng text, dùng regex bóc ra IP / loại sự kiện / mức độ.
     3. GỬI   : đóng gói thành JSON, POST sang webhook của n8n.

  Nó chạy TRÊN CHÍNH máy n8n (192.168.10.2), nên về kiến trúc vẫn thuộc
  "khối n8n", không phải server thứ tư.

LUỒNG 1 GÓI TIN:
  pfSense --UDP:514--> [recvfrom nhận] --> [parse_line dịch] --> [POST] --> n8n
========================================================================
"""

import socket                    # thư viện mạng cấp thấp: tạo "ổ cắm" UDP để nghe
import json                      # đóng gói dữ liệu thành chuỗi JSON
import re                        # regex: bóc tách thông tin từ dòng text
import logging                   # ghi log ra file
import urllib.request            # gửi HTTP POST (không cần cài thêm 'requests')
from logging.handlers import RotatingFileHandler   # file log tự xoay vòng
from datetime import datetime, timezone


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 1 — CẤU HÌNH                                                 ║
# ║ Đây là các thông số Khải chỉnh tùy môi trường.                   ║
# ╚══════════════════════════════════════════════════════════════════╝

LISTEN_IP   = "0.0.0.0"
#   ^ "0.0.0.0" = nghe trên MỌI card mạng của máy n8n (192.168.10.2).
#     Đây là IP CỦA CHÍNH MÁY N8N, không phải IP pfSense.
#     (Đừng đổi thành 192.168.10.1 — đó là nhà hàng xóm, sẽ lỗi bind.)

LISTEN_PORT = 514
#   ^ Cổng chờ nhận. PHẢI khớp với port ghi trong pfSense
#     (Remote log servers = 192.168.10.2:514). pfSense gửi tới 514,
#     nên ở đây cũng phải nghe 514.

N8N_WEBHOOK = "http://127.0.0.1:5678/webhook/pfsense-event"
#   ^ Địa chỉ webhook của WF-00. Vì forwarder chạy CÙNG máy với n8n
#     nên dùng 127.0.0.1 (localhost) là được.

# --- AI ĐƯỢC PHÉP GỬI SYSLOG CHO TA? ---
PFSENSE_IP = "192.168.10.1"
#   ^ IP của pfSense. Ta dùng nó để KIỂM TRA gói đến có đúng từ pfSense không.

ONLY_ACCEPT_FROM_PFSENSE = False
#   ^ True  = CHỈ xử lý gói gửi từ 192.168.10.1 (bảo mật hơn, production).
#     False = nhận từ bất kỳ đâu (tiện cho lúc test, bắn UDP giả từ localhost).

SITE = "HCM-01"
DEBUG_FORWARD_ALL = False
#   ^ True = forward CẢ log không nhận diện được (gắn nhãn UNKNOWN) — chỉ để debug.
#     False = chỉ forward event an ninh thật (bỏ qua DNS/NTP/log nền).

INTERNAL_NETS = ["192.168.10.", "192.168.11.", "192.168.12.", "192.168.20."]
#   ^ Các dải mạng NỘI BỘ. IP thuộc các dải này KHÔNG bị coi là attacker
#     (tránh block nhầm hạ tầng của chính mình).

# --- Cấu hình file log xoay vòng ---
LOG_FILE      = "forwarded_events.log"
LOG_MAX_BYTES = 10 * 1024 * 1024   # mỗi file tối đa 10 MB
LOG_BACKUP    = 5                  # giữ 5 file gần nhất, cũ hơn thì xóa


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 2 — BỘ GHI LOG RA FILE (rotating)                            ║
# ║ Lưu lại các event ĐÃ forward, phục vụ backup và điều tra sự cố.  ║
# ╚══════════════════════════════════════════════════════════════════╝

logger = logging.getLogger("forwarder")
logger.setLevel(logging.INFO)
_fh = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES,
                          backupCount=LOG_BACKUP, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger.addHandler(_fh)
#   ^ RotatingFileHandler tự động: khi file đầy 10MB → đổi tên thành .1,
#     tạo file mới. Giữ tối đa 5 file cũ. Nhờ vậy log không phình vô hạn.


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 3 — CÁC MẪU REGEX ĐỂ BÓC TÁCH DÒNG SYSLOG                    ║
# ╚══════════════════════════════════════════════════════════════════╝

# Regex cho alert Suricata (định dạng fast.log):
RE_PRIORITY = re.compile(r"\[Priority:\s*(\d+)\]")          # bóc [Priority: 1]
RE_MSG      = re.compile(r"\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]")  # tên rule
RE_CLASS    = re.compile(r"\[Classification:\s*(.*?)\]")    # phân loại
RE_FLOW     = re.compile(r"\{(\w+)\}\s+([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)")
#   ^ RE_FLOW bóc: {TCP} 192.168.183.133:40000 -> 192.168.10.1:80
#     group(1)=proto  group(2)=src_ip  group(3)=src_port
#     group(4)=dst_ip group(5)=dst_port

RE_ANY_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")    # bắt mọi IPv4
RE_MAC    = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")  # bắt MAC


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 4 — CÁC HÀM PHỤ TRỢ                                          ║
# ╚══════════════════════════════════════════════════════════════════╝

def severity_from_priority(prio: str) -> str:
    """Suricata Priority 1/2/3 -> mức độ HIGH/MEDIUM/LOW."""
    return {"1": "HIGH", "2": "MEDIUM", "3": "LOW"}.get(prio, "MEDIUM")


def is_internal(ip: str) -> bool:
    """IP này có thuộc mạng nội bộ không? (để không block nhầm)."""
    return bool(ip) and any(ip.startswith(net) for net in INTERNAL_NETS)


def pick_attacker(src: str, dst: str):
    """Trong 2 IP, chọn IP KHÔNG thuộc nội bộ làm attacker."""
    if src and not is_internal(src):
        return src
    if dst and not is_internal(dst):
        return dst
    return src or dst


def classify_suricata(msg: str, classification: str) -> str:
    """Dựa vào tên rule + phân loại, quy về event_type mà WF-00 hiểu."""
    text = (msg + " " + classification).lower()
    if "brute" in text or "ssh scan" in text:
        return "BRUTE_FORCE"
    if "scan" in text or "information leak" in text:
        return "PORT_SCAN"
    if "dos" in text or "flood" in text:
        return "HIGH_BANDWIDTH"
    return "IDS_ALERT"


def parse_filterlog(raw: str):
    """
    Parse log FIREWALL (filterlog) — sinh ra khi pfSense CHẶN một gói tin.
    Đây là nguồn tín hiệu CHÍNH khi Suricata chưa bật: nếu 1 IP lạ bị chặn
    liên tục thì rất có thể đang quét cổng.
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
    if is_internal(attacker):        # nếu cả 2 đều nội bộ -> bỏ qua
        return None
    return {
        "event_type": "PORT_SCAN",
        "src_ip": attacker,
        "dst_ip": dst if attacker == src else src,
        "protocol": "tcp" if ",tcp," in raw.lower() else None,
        "severity": "MEDIUM",
        "message": "firewall block (filterlog)",
        "detector": "filterlog",
    }


def parse_line(raw: str):
    """
    Trái tim của forwarder: nhận 1 DÒNG syslog thô, thử khớp lần lượt
    từng loại. Trả về dict (nếu nhận diện được) hoặc None (bỏ qua).
    """
    low = raw.lower()

    # (1) Alert Suricata — ưu tiên cao nhất vì IDS đã phân tích sẵn
    if "[**]" in raw and RE_FLOW.search(raw):
        flow = RE_FLOW.search(raw)
        prio = RE_PRIORITY.search(raw).group(1) if RE_PRIORITY.search(raw) else "2"
        msg  = RE_MSG.search(raw).group(1) if RE_MSG.search(raw) else ""
        clz  = RE_CLASS.search(raw).group(1) if RE_CLASS.search(raw) else ""
        src, dst = flow.group(2), flow.group(4)
        return {
            "event_type": classify_suricata(msg, clz),
            "src_ip": pick_attacker(src, dst),
            "dst_ip": dst,
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

    # (3) Thiết bị mới (DHCP cấp lease)
    if "dhcp" in low and ("dhcpack" in low or "new lease" in low) and RE_MAC.search(raw):
        ips = RE_ANY_IP.findall(raw)
        return {
            "event_type": "NEW_MAC",
            "src_ip": ips[0] if ips else None,
            "dst_ip": None, "protocol": "DHCP", "severity": "LOW",
            "message": RE_MAC.search(raw).group(1), "detector": "dhcp",
        }

    # (4) Firewall block (filterlog)
    fw = parse_filterlog(raw)
    if fw:
        return fw

    # (5) Không khớp gì — chỉ forward khi bật DEBUG
    if DEBUG_FORWARD_ALL:
        return {
            "event_type": "UNKNOWN",
            "src_ip": (RE_ANY_IP.findall(raw) or [None])[0],
            "dst_ip": None, "protocol": None, "severity": "LOW",
            "message": raw[-200:], "detector": "debug",
        }
    return None


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


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 5 — VÒNG LẶP CHÍNH: NƠI NHẬN TÍN HIỆU TỪ pfSense            ║
# ║ >>> ĐÂY CHÍNH LÀ CHỖ KHẢI HỎI <<<                                ║
# ╚══════════════════════════════════════════════════════════════════╝

def main():
    # --- Mở "ổ cắm" UDP và gắn vào port 514 của máy n8n ---
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # SOCK_DGRAM = UDP
    sock.bind((LISTEN_IP, LISTEN_PORT))
    #   ^ Sau dòng này, mọi gói UDP gửi tới 192.168.10.2:514 sẽ vào socket này.

    print(f"[forwarder] nghe syslog UDP {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[forwarder] chi nhan tu pfSense? {ONLY_ACCEPT_FROM_PFSENSE} (pfSense={PFSENSE_IP})")
    print(f"[forwarder] forward toi {N8N_WEBHOOK}")
    print(f"[forwarder] ghi log vao {LOG_FILE}\n")

    while True:
        # ============================================================
        # ĐÂY LÀ DÒNG NHẬN TÍN HIỆU TỪ pfSense (10.1):
        #   - Chương trình DỪNG ở đây, ngồi chờ tới khi có gói UDP đến.
        #   - Khi pfSense bắn 1 dòng syslog sang, recvfrom() "tỉnh dậy".
        #   - Nó trả về 2 thứ:
        #       data = nội dung log (dạng bytes)
        #       addr = (IP_người_gửi, port_người_gửi)
        #   - => addr[0] CHÍNH LÀ IP CỦA pfSense = "192.168.10.1"
        #        Đây là cách ta BIẾT tín hiệu đến từ pfSense.
        # ============================================================
        data, addr = sock.recvfrom(8192)
        sender_ip = addr[0]           # <-- IP người gửi. Với pfSense = 192.168.10.1

        # --- (Tùy chọn) Lọc: chỉ xử lý nếu đúng là pfSense gửi ---
        if ONLY_ACCEPT_FROM_PFSENSE and sender_ip != PFSENSE_IP:
            # Gói đến từ IP khác pfSense -> bỏ qua (chống giả mạo log)
            continue

        # --- Đổi bytes thành chuỗi text để đọc ---
        raw = data.decode("utf-8", errors="replace").strip()

        # --- DỊCH: parse dòng text thành dict có cấu trúc ---
        parsed = parse_line(raw)
        if not parsed:
            # Log nền (DNS/NTP/...) không nhận diện được -> bỏ qua, chờ gói kế
            continue

        # --- Gắn thêm metadata: thời gian, site, VÀ ai đã gửi ---
        parsed.update({
            "event_id": f"evt-{int(datetime.now().timestamp()*1000)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "site": SITE,
            "source_host": sender_ip,   # <-- lưu lại IP pfSense đã gửi (để truy vết)
        })

        # --- In ra màn hình cho Khải nhìn thấy tín hiệu ---
        print(f"[{datetime.now().strftime('%H:%M:%S')}] tu {sender_ip} -> "
              f"{parsed['event_type']} (src={parsed.get('src_ip')}, by={parsed.get('detector')})")

        # --- GỬI: POST sang n8n ---
        status = post_to_n8n(parsed)

        # --- Ghi log ra file (backup + forensics) ---
        logger.info(json.dumps({**parsed, "n8n_status": status}, ensure_ascii=False))


if __name__ == "__main__":
    main()
