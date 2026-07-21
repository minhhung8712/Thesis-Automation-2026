#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================
 pf_collector.py — BỘ THU LOG pfSense (UDP syslog) -> FILE + N8N
========================================================================

VAI TRÒ (CHỈ thu thập & lưu trữ, KHÔNG phân tích):
  1. NGHE syslog UDP từ pfSense (mặc định port 514).
  2. (Tuỳ chọn) GỬI NGUYÊN VĂN từng dòng sang webhook N8N.
  3. GHI từng dòng vào file, kèm TIMESTAMP THU NHẬN (ISO8601 UTC) ở đầu
     dòng, phân cách bằng TAB.
  4. Rotate khi file active đạt 5MB.

*** ĐIỂM MỚI — ĐỊNH TUYẾN 2 LUỒNG LOG ***
  Collector nghe CHUNG 1 cổng UDP 514 (pfSense chỉ gửi được về 1 đích),
  nhưng GHI RA 2 FILE tuỳ theo NGUỒN của dòng log:

    - Dòng của tiến trình dhcpd (DHCPDISCOVER/REQUEST/OFFER/ACK...) 
        -> ghi vào  dhcp.log      (WF-DHCP-WATCH đọc file ACTIVE này)
    - Mọi dòng còn lại (filterlog, sshd, system, ipsec, openvpn...)
        -> ghi vào  pfsense.log   (WF-ANALYZER đọc; pf_analyzer.py đọc
                                    các file pfsense_*.log đã rotate)

  Nhờ tách nguồn: pfsense.log không lẫn rác DHCP (WF-ANALYZER quét nhẹ
  hơn), và dhcp.log chỉ chứa sự kiện cấp phát IP (WF-DHCP-WATCH parse
  MAC/hostname gọn gàng). Hai file rotate ĐỘC LẬP với 2 tiền tố khác nhau
  (pfsense_*.log vs dhcp_*.log) nên pf_analyzer.py — vốn tìm pfsense_*.log
  — KHÔNG bao giờ vô tình nuốt nhầm file DHCP.
========================================================================
"""

import socket
import json
import os
import urllib.request
from datetime import datetime, timezone


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 1 — CẤU HÌNH                                                 ║
# ╚══════════════════════════════════════════════════════════════════╝

LISTEN_IP   = "0.0.0.0"        # nghe trên MỌI card mạng của máy chạy collector
LISTEN_PORT = 514              # khớp port pfSense gửi syslog tới

PFSENSE_IP  = "192.168.10.1"
ONLY_ACCEPT_FROM_PFSENSE = False   # True = chỉ nhận gói từ pfSense (nên bật ở production)

N8N_WEBHOOK    = "http://127.0.0.1:5678/webhook/pfsense-raw"   # webhook nhận RAW log
FORWARD_TO_N8N = False     # False = tắt forward n8n, chỉ ghi file (hữu ích khi debug/offline)
N8N_TIMEOUT    = 3        # giây — KHÔNG chờ n8n lâu, tránh nghẽn vòng lặp nhận UDP

SITE = "HCM-01"           # gắn kèm mỗi payload gửi n8n, để phân biệt nếu có nhiều site

LOG_DIR = r"C:\Users\Administrator\.n8n-files\pflogs"   # thư mục chứa các file log

# --- 2 luồng log active (mỗi luồng 1 tên file cố định + 1 tiền tố rotate) ---
ACTIVE_LOG_NAME = "pfsense.log"   # firewall/auth/system  -> WF-ANALYZER / pf_analyzer.py
PFSENSE_PREFIX  = "pfsense"       # rotate -> pfsense_<ts>.log

DHCP_LOG_NAME   = "dhcp.log"      # CHỈ dhcpd            -> WF-DHCP-WATCH (đọc file active)
DHCP_PREFIX     = "dhcp"          # rotate -> dhcp_<ts>.log

ROTATE_MAX_BYTES = 5 * 1024 * 1024   # 5 MB -> rotate sang file mới có timestamp


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 2 — NHẬN DIỆN DÒNG DHCP                                      ║
# ╚══════════════════════════════════════════════════════════════════╝

# Từ khoá bản tin DHCP (đủ để bắt cả trường hợp process name bị cắt).
_DHCP_KEYWORDS = (
    "DHCPDISCOVER", "DHCPREQUEST", "DHCPOFFER", "DHCPACK",
    "DHCPNAK", "DHCPDECLINE", "DHCPRELEASE", "DHCPINFORM",
)


def is_dhcp_line(raw: str) -> bool:
    """True nếu dòng log đến từ dịch vụ DHCP của pfSense.
    Ưu tiên khớp tên tiến trình 'dhcpd' (chuẩn nhất, xem screenshot log:
    Process = dhcpd); fallback bắt theo từ khoá bản tin DHCP phòng khi
    định dạng syslog khác nhau."""
    low = raw.lower()
    if "dhcpd" in low:
        return True
    return any(k in raw for k in _DHCP_KEYWORDS)


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 3 — GHI FILE + ROTATE (DÙNG CHUNG CHO CẢ 2 LUỒNG)            ║
# ╚══════════════════════════════════════════════════════════════════╝

def _rotate_if_needed(active_name: str, prefix: str):
    """Nếu file active đã >= 5MB -> đổi tên thành <prefix>_<timestamp>.log.
    Lần ghi kế tiếp tự tạo file active mới (trống) vì open(...,'a') tự tạo.

    Tên có timestamp (kèm microsecond) để: sort tên = sort thời gian,
    không trùng dù rotate liên tiếp trong 1 giây, và phân biệt rõ file
    'đã đóng' (<prefix>_*.log) với file 'đang active' (<active_name>)."""
    path = os.path.join(LOG_DIR, active_name)
    if not os.path.exists(path):
        return
    if os.path.getsize(path) < ROTATE_MAX_BYTES:
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    new_path = os.path.join(LOG_DIR, f"{prefix}_{ts}.log")
    os.rename(path, new_path)   # os.rename ATOMIC trên cùng filesystem -> an toàn
    print(f"[collector] rotate: {active_name} "
          f"(>= {ROTATE_MAX_BYTES/1024/1024:.0f}MB) -> {os.path.basename(new_path)}")


def write_line(active_name: str, prefix: str, raw: str):
    """Ghi 1 dòng vào file active tương ứng, kèm timestamp thu nhận
    (ISO8601 UTC) ở đầu dòng, phân cách bằng TAB. Kiểm tra rotate TRƯỚC
    khi ghi để không dòng nào lọt vào file đã vượt 5MB."""
    _rotate_if_needed(active_name, prefix)
    ts = datetime.now(timezone.utc).isoformat()
    line = f"{ts}\t{raw}\n"
    with open(os.path.join(LOG_DIR, active_name), "a", encoding="utf-8") as f:
        f.write(line)


def route_and_write(raw: str):
    """ĐỊNH TUYẾN: dhcpd -> dhcp.log ; còn lại -> pfsense.log."""
    if is_dhcp_line(raw):
        write_line(DHCP_LOG_NAME, DHCP_PREFIX, raw)
    else:
        write_line(ACTIVE_LOG_NAME, PFSENSE_PREFIX, raw)


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 4 — FORWARD SANG N8N (giữ nguyên, best-effort)              ║
# ╚══════════════════════════════════════════════════════════════════╝

def forward_to_n8n(raw: str, sender_ip: str):
    """Gửi nguyên văn dòng log sang webhook N8N (best-effort — n8n down/chậm
    thì chỉ in lỗi, KHÔNG gián đoạn ghi file hay vòng lặp nhận UDP)."""
    if not FORWARD_TO_N8N:
        return
    payload = {
        "raw": raw,
        "received_at": datetime.now(timezone.utc).isoformat(),
        "source_host": sender_ip,
        "site": SITE,
        "is_dhcp": is_dhcp_line(raw),   # tiện cho n8n lọc nhanh nếu cần
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        N8N_WEBHOOK, data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=N8N_TIMEOUT):
            pass
    except Exception as e:
        print(f"  !! forward n8n loi: {e}")


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 5 — VÒNG LẶP CHÍNH: NHẬN SYSLOG TỪ pfSense                   ║
# ╚══════════════════════════════════════════════════════════════════╝

def main():
    os.makedirs(LOG_DIR, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[collector] nghe syslog UDP {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[collector] pfsense.log <- firewall/auth/system  (WF-ANALYZER)")
    print(f"[collector] dhcp.log    <- dhcpd                  (WF-DHCP-WATCH)")
    print(f"[collector] thu muc: {LOG_DIR}  (rotate {ROTATE_MAX_BYTES/1024/1024:.0f}MB)")
    print(f"[collector] forward n8n: {'BAT' if FORWARD_TO_N8N else 'TAT'} -> {N8N_WEBHOOK}\n")

    while True:
        data, addr = sock.recvfrom(8192)
        sender_ip = addr[0]

        if ONLY_ACCEPT_FROM_PFSENSE and sender_ip != PFSENSE_IP:
            continue

        raw = data.decode("utf-8", errors="replace").strip()
        if not raw:
            continue

        route_and_write(raw)          # <-- thay cho write_log(raw): tự tách 2 luồng
        forward_to_n8n(raw, sender_ip)


if __name__ == "__main__":
    main()
