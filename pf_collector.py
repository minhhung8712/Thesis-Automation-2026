#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================
 pf_collector.py — BỘ THU LOG pfSense (UDP syslog) -> N8N + FILE pfsense.log
========================================================================

VAI TRÒ (CHỈ 1 VIỆC DUY NHẤT — thu thập & lưu trữ, KHÔNG phân tích):
  1. NGHE syslog UDP từ pfSense (mặc định port 514).
  2. GỬI NGUYÊN VĂN từng dòng log sang webhook N8N (để n8n có log real-time,
     có thể dùng cho dashboard/alerting riêng nếu muốn).
  3. GHI từng dòng vào file pfsense.log, kèm TIMESTAMP THU NHẬN (ISO8601,
     UTC) ở đầu dòng, phân cách bằng TAB.
  4. Khi pfsense.log đạt 5MB -> ĐÓNG file (đổi tên thành
     pfsense_<timestamp>.log), lần ghi kế tiếp tự tạo pfsense.log MỚI trống.

File này KHÔNG phân tích/phân loại tấn công — việc đó do pf_analyzer.py
đảm nhiệm (đọc các file pfsense_*.log ĐÃ ĐÓNG, không bao giờ đụng vào
pfsense.log đang active vì file đó còn đang được ghi tiếp).

LÝ DO ghi timestamp thu nhận vào đầu mỗi dòng:
  pfSense có thể gửi log ở nhiều định dạng thời gian khác nhau tùy nguồn
  (filterlog, sshd auth log...) — parse lại cho chính xác khá
  rắc rối. Dùng thời điểm collector THỰC SỰ nhận được gói UDP làm mốc
  "now" cho cửa sổ trượt bên pf_analyzer.py vừa đơn giản vừa đủ chính xác
  cho mục đích phát hiện tấn công theo thời gian thực.
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
FORWARD_TO_N8N = True     # False = tắt forward n8n, chỉ ghi file (hữu ích khi debug/offline)
N8N_TIMEOUT    = 3        # giây — KHÔNG chờ n8n lâu, tránh nghẽn vòng lặp nhận UDP

SITE = "HCM-01"           # gắn kèm mỗi payload gửi n8n, để phân biệt nếu có nhiều site

LOG_DIR = r"C:\Users\Administrator\.n8n-files\pflogs"       # thư mục chứa pfsense.log + các file đã rotate
ACTIVE_LOG_NAME  = "pfsense.log"     # tên file đang ghi (LUÔN LUÔN cố định tên này khi active)
ROTATE_MAX_BYTES = 5 * 1024 * 1024   # 5 MB -> rotate sang file mới có timestamp


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 2 — GHI FILE + ROTATE                                        ║
# ╚══════════════════════════════════════════════════════════════════╝

def _active_log_path() -> str:
    return os.path.join(LOG_DIR, ACTIVE_LOG_NAME)


def _rotate_if_needed():
    """Nếu pfsense.log đã >= 5MB -> đổi tên thành pfsense_<timestamp>.log.
    Lần ghi kế tiếp sẽ tự tạo pfsense.log mới (trống) vì open(...,'a') tự
    tạo file nếu chưa tồn tại.

    Đặt tên có timestamp (kèm microsecond) để:
      - pf_analyzer.py biết THỨ TỰ xử lý (sort tên = sort theo thời gian).
      - Không bao giờ trùng tên dù rotate liên tiếp trong cùng 1 giây.
      - pf_analyzer.py phân biệt rõ file "đã đóng" (pfsense_*.log, an toàn
        để đọc/xử lý/di chuyển) với file "đang active" (pfsense.log, đang
        được collector ghi tiếp — TUYỆT ĐỐI không được đụng vào)."""
    path = _active_log_path()
    if not os.path.exists(path):
        return
    if os.path.getsize(path) < ROTATE_MAX_BYTES:
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    new_path = os.path.join(LOG_DIR, f"pfsense_{ts}.log")
    os.rename(path, new_path)   # os.rename là ATOMIC trên cùng filesystem -> an toàn
    print(f"[collector] rotate: {ACTIVE_LOG_NAME} "
          f"(>= {ROTATE_MAX_BYTES/1024/1024:.0f}MB) -> {os.path.basename(new_path)}")


def write_log(raw: str):
    """Ghi 1 dòng vào pfsense.log, kèm timestamp thu nhận (ISO8601) ở đầu
    dòng, phân cách bằng TAB. Kiểm tra rotate TRƯỚC khi ghi để không dòng
    nào bị viết vào file đã vượt ngưỡng 5MB."""
    _rotate_if_needed()
    ts = datetime.now(timezone.utc).isoformat()
    line = f"{ts}\t{raw}\n"
    with open(_active_log_path(), "a", encoding="utf-8") as f:
        f.write(line)


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 3 — FORWARD SANG N8N                                         ║
# ╚══════════════════════════════════════════════════════════════════╝

def forward_to_n8n(raw: str, sender_ip: str):
    """Gửi nguyên văn dòng log sang webhook N8N (best-effort — nếu n8n
    down/chậm thì chỉ in lỗi ra console, KHÔNG làm gián đoạn việc ghi file
    hay vòng lặp nhận UDP)."""
    if not FORWARD_TO_N8N:
        return
    payload = {
        "raw": raw,
        "received_at": datetime.now(timezone.utc).isoformat(),
        "source_host": sender_ip,
        "site": SITE,
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
# ║ PHẦN 4 — VÒNG LẶP CHÍNH: NHẬN SYSLOG TỪ pfSense                   ║
# ╚══════════════════════════════════════════════════════════════════╝

def main():
    os.makedirs(LOG_DIR, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[collector] nghe syslog UDP {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[collector] ghi log tai {_active_log_path()} "
          f"(rotate {ROTATE_MAX_BYTES/1024/1024:.0f}MB)")
    print(f"[collector] forward n8n: {'BAT' if FORWARD_TO_N8N else 'TAT'} -> {N8N_WEBHOOK}\n")

    while True:
        data, addr = sock.recvfrom(8192)
        sender_ip = addr[0]

        if ONLY_ACCEPT_FROM_PFSENSE and sender_ip != PFSENSE_IP:
            continue

        raw = data.decode("utf-8", errors="replace").strip()
        if not raw:
            continue

        write_log(raw)
        forward_to_n8n(raw, sender_ip)


if __name__ == "__main__":
    main()
