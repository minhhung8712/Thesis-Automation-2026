#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================
 pf_analyzer.py — PHÂN TÍCH LOG pfSense -> PHÂN LOẠI IP TẤN CÔNG
========================================================================

VAI TRÒ:
  1. Quét thư mục LOG_DIR, tìm các file ĐÃ ĐÓNG (pfsense_*.log — do
     pf_collector.py rotate ra khi pfsense.log đạt 5MB). TUYỆT ĐỐI KHÔNG
     đụng vào pfsense.log (đang được collector ghi tiếp).
  2. Đọc từng dòng, đưa qua ENGINE PHÁT HIỆN THEO NGƯỠNG (sliding window)
     — cùng logic BRUTE_FORCE / PORT_SCAN / SYN_FLOOD / CONN_FLOOD / DDoS
     phân tán đã dùng ở bản forwarder.py trước đây.
  3. Khi 1 IP vượt ngưỡng -> ghi vào ĐÚNG 1 trong 3 file phân loại:
        BanIP_Scanport.txt    <- PORT_SCAN
        BanIP_Bruteforce.txt  <- BRUTE_FORCE
        BanIP_DDOS.txt        <- CONN_FLOOD / SYN_FLOOD / DDoS phân tán
     (mỗi dòng 1 IP, KHÔNG trùng lặp — N8N sẽ đọc định kỳ 3 file này để
     gọi API Ansible khóa IP trên pfSense.)
  4. Sau khi xử lý XONG 1 file pfsense_*.log -> CHUYỂN (move) file đó vào
     thư mục BKLOG/ để lưu trữ (KHÔNG xóa — phục vụ điều tra/forensics).
  5. Lặp lại theo chu kỳ POLL_INTERVAL giây (chạy nền liên tục).

GHI CHÚ VỀ MỐC THỜI GIAN "now" CHO CỬA SỔ TRƯỢT:
  Mỗi dòng trong pfsense_*.log được pf_collector.py ghi kèm timestamp thu
  nhận (ISO8601) ở đầu dòng, phân cách bằng TAB. pf_analyzer.py dùng CHÍNH
  timestamp đó làm "now" khi tính cửa sổ trượt (window) — thay vì dùng thời
  điểm xử lý thực tế (có thể trễ nếu file tồn đọng) hay parse timestamp thô
  của pfSense (rắc rối vì nhiều định dạng khác nhau tùy nguồn log).

GHI CHÚ VỀ CÁC SỰ KIỆN "TỨC THỜI" (VPN_TUNNEL_DOWN / NEW_MAC):
  Các sự kiện hạ tầng này KHÔNG liên quan tới 1 IP tấn công cụ thể nên
  KHÔNG được ghi vào 3 file ban — chỉ ghi vào analyzer_events.log để có
  dấu vết audit. Muốn cảnh báo các sự kiện này real-time thì xử lý ở phía
  N8N dựa trên raw log mà pf_collector.py đã forward sang.
========================================================================
"""

import os
import re
import glob
import json
import shutil
import time
import logging
from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler
from datetime import datetime


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 1 — CẤU HÌNH                                                 ║
# ╚══════════════════════════════════════════════════════════════════╝

LOG_DIR         = "./pflogs"          # PHẢI trùng LOG_DIR bên pf_collector.py
ACTIVE_LOG_NAME = "pfsense.log"       # tên file active -> KHÔNG BAO GIỜ xử lý file này
FILE_PATTERN    = "pfsense_*.log"     # pattern các file ĐÃ ĐÓNG (đã rotate)

BKLOG_DIR     = "./BKLOG"             # nơi lưu trữ file đã xử lý xong
POLL_INTERVAL = 10                    # giây — chu kỳ quét thư mục tìm file mới

# --- 3 file phân loại IP ban (N8N sẽ đọc các file này) ---
BAN_SCANPORT   = "BanIP_Scanport.txt"
BAN_BRUTEFORCE = "BanIP_Bruteforce.txt"
BAN_DDOS       = "BanIP_DDOS.txt"

# Dải mạng NỘI BỘ — IP thuộc đây KHÔNG bao giờ bị coi là attacker (chống tự block)
INTERNAL_NETS = ["192.168.10.", "192.168.11.", "192.168.12.", "192.168.20."]

# IP hạ tầng / noise — bỏ qua theo TIỀN TỐ
IGNORE_PREFIXES = ["169.254.", "224.", "239.", "255.", "0.", "127."]

# IP bỏ qua theo KHỚP CHÍNH XÁC (tách riêng để tránh khớp nhầm tiền tố)
IGNORE_EXACT = ["192.168.183.1", "192.168.10.1"]

# ----- NGƯỠNG PHÁT HIỆN (giữ nguyên căn cứ như bản trước) -----
THRESHOLDS = {
    "BRUTE_FORCE": {"count": 5,           "window": 60},   # 5 lan fail / 60s (cung 1 port)
    "PORT_SCAN":   {"distinct_ports": 15, "window": 10},   # 15 port khac nhau / 10s
    "CONN_FLOOD":  {"count": 100,         "window": 10},   # 100 su kien / 10s (DoS 1 nguon)
    "SYN_FLOOD":   {"count": 30,          "window": 5},    # >= 30 goi SYN thuan / 5s / 1 IP
    "DDOS_VOLUME": {"count": 500,         "window": 10},   # tong moi IP > 500 event/10s
    "DDOS_SPREAD": {"distinct_ips": 20,   "window": 10},   # > 20 IP khac nhau cung tan cong
}

MAX_TRACKED_IPS = 5000   # giới hạn số IP theo dõi cùng lúc (chống phình bộ nhớ)

# Ánh xạ event_type -> file ban tương ứng (3 nhóm theo yêu cầu)
BAN_FILE_MAP = {
    "PORT_SCAN":   BAN_SCANPORT,
    "BRUTE_FORCE": BAN_BRUTEFORCE,
    "CONN_FLOOD":  BAN_DDOS,
    "SYN_FLOOD":   BAN_DDOS,
    "DDOS":        BAN_DDOS,
}

# File log audit nội bộ (rotate riêng, không phải file ban)
LOG_FILE      = "analyzer_events.log"
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP    = 5


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 2 — LOGGER AUDIT + QUẢN LÝ 3 FILE BAN IP                     ║
# ╚══════════════════════════════════════════════════════════════════╝

logger = logging.getLogger("analyzer")
logger.setLevel(logging.INFO)
_fh = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES,
                          backupCount=LOG_BACKUP, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger.addHandler(_fh)


def _load_ip_set(path: str) -> set:
    """Nạp danh sách IP đã ban từ trước (nếu file tồn tại) -> chống ghi trùng."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return {ln.strip() for ln in f if ln.strip()}
    except FileNotFoundError:
        return set()


_banned = {
    BAN_SCANPORT:   _load_ip_set(BAN_SCANPORT),
    BAN_BRUTEFORCE: _load_ip_set(BAN_BRUTEFORCE),
    BAN_DDOS:       _load_ip_set(BAN_DDOS),
}


def ban_ip(ip: str, event_type: str):
    """Ghi IP vào ĐÚNG 1 trong 3 file phân loại theo event_type.
    Không ghi trùng dòng (dùng set trong bộ nhớ để kiểm tra nhanh)."""
    target = BAN_FILE_MAP.get(event_type)
    if not target or not ip:
        return False
    ipset = _banned[target]
    if ip in ipset:
        return False
    ipset.add(ip)
    try:
        with open(target, "a", encoding="utf-8") as f:
            f.write(ip + "\n")
        print(f"  -> ban {ip} vao {target} (ly do: {event_type})")
        return True
    except Exception as e:
        print(f"  !! ghi {target} that bai: {e}")
        ipset.discard(ip)
        return False


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 3 — CÁC MẪU REGEX ĐỂ BÓC TÁCH DÒNG SYSLOG                    ║
# ╚══════════════════════════════════════════════════════════════════╝

# --- Suricata fast.log (IDS) ---
RE_PRIORITY = re.compile(r"\[Priority:\s*(\d+)\]")
RE_MSG      = re.compile(r"\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]")
RE_CLASS    = re.compile(r"\[Classification:\s*(.*?)\]")
RE_FLOW     = re.compile(r"\{(\w+)\}\s+([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)")

# --- Tiện ích ---
RE_ANY_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
RE_MAC    = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")

# --- Filterlog (firewall): ...,src_ip,dst_ip,sport,dport,... ---
RE_FILTERLOG_PORTS = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}),(\d{1,3}(?:\.\d{1,3}){3}),(\d+),(\d+)")

# --- Filterlog: hành động pass/block ---
#   QUAN TRỌNG: phải xét CẢ "pass" lẫn "block". Nhiều DDoS/SYN flood nhắm
#   vào port đang MỞ (vd web server :80) nên pfSense ghi "pass", không phải
#   "block". Nếu chỉ bắt "block" thì loại tấn công phổ biến nhất sẽ lọt lưới.
RE_FW_ACTION = re.compile(r",(pass|block),")

# --- Filterlog TCP: bóc thêm cờ TCP (flags) để phát hiện SYN FLOOD ---
#   flags = "S"  -> CHỈ cờ SYN, không ACK -> đặc trưng SYN flood
#   flags = "SA" -> SYN-ACK bình thường (không phải flood)
RE_FILTERLOG_TCP = re.compile(
    r"tcp,\d+,(\d{1,3}(?:\.\d{1,3}){3}),(\d{1,3}(?:\.\d{1,3}){3}),(\d+),(\d+),\d+,([A-Z]*)")

# --- Auth log (sshd) — BẰNG CHỨNG TRỰC TIẾP cho brute force ---
RE_SSH_FAIL    = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)")
RE_SSH_INVALID = re.compile(r"Invalid user (\S+) from ([\d.]+)")


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 4 — HÀM PHỤ TRỢ PHÂN LOẠI IP                                 ║
# ╚══════════════════════════════════════════════════════════════════╝

def is_internal(ip: str) -> bool:
    return bool(ip) and any(ip.startswith(net) for net in INTERNAL_NETS)


def should_ignore(ip: str) -> bool:
    if not ip:
        return True
    if ip in IGNORE_EXACT:
        return True
    return any(ip.startswith(p) for p in IGNORE_PREFIXES)


def pick_attacker(src: str, dst: str):
    """Trong 2 IP của 1 gói, chọn IP KHÔNG thuộc nội bộ làm attacker."""
    if src and not is_internal(src):
        return src
    if dst and not is_internal(dst):
        return dst
    return src or dst


def classify_suricata(msg: str, classification: str) -> str:
    text = (msg + " " + classification).lower()
    if "brute" in text or "ssh scan" in text or "login" in text:
        return "BRUTE_FORCE"
    if "scan" in text or "information leak" in text:
        return "PORT_SCAN"
    if "dos" in text or "flood" in text:
        return "CONN_FLOOD"
    return "IDS_ALERT"


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 5 — ENGINE PHÁT HIỆN THEO NGƯỠNG (sliding window)            ║
# ╚══════════════════════════════════════════════════════════════════╝

_events = defaultdict(deque)     # IP -> deque[(timestamp, dst_port, kind)]
_MAX_WINDOW = 60

_global_events = deque()         # bộ đếm TỔNG toàn hệ thống (cho DDoS phân tán)


def _global_record(ip, now):
    _global_events.append((now, ip))
    cutoff = now - THRESHOLDS["DDOS_VOLUME"]["window"]
    while _global_events and _global_events[0][0] < cutoff:
        _global_events.popleft()
    total = len(_global_events)
    distinct_ips = len({src for _, src in _global_events})
    return total, distinct_ips


def _trim(dq, now):
    cutoff = now - _MAX_WINDOW
    while dq and dq[0][0] < cutoff:
        dq.popleft()


def _count(dq, now, window, kind=None, port=None):
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
    cutoff = now - window
    ports = set()
    for ts, p, k in dq:
        if ts >= cutoff and (kind is None or k == kind) and p is not None:
            ports.add(p)
    return len(ports)


def record_and_detect(ip, dport, kind, now=None):
    """Ghi 1 tín hiệu thô vào tracker của IP, rồi xét ngưỡng.
    Trả về (event_type, metric) nếu vượt ngưỡng, ngược lại None.
    Thứ tự xét: BRUTE_FORCE -> SYN_FLOOD -> CONN_FLOOD -> PORT_SCAN -> DDoS."""
    if now is None:
        now = time.time()

    if len(_events) > MAX_TRACKED_IPS:
        for k in list(_events.keys()):
            _trim(_events[k], now)
            if not _events[k]:
                del _events[k]

    dq = _events[ip]
    dq.append((now, dport, kind))
    _trim(dq, now)

    # (1) BRUTE_FORCE: nhiều lần 'auth_fail' vào CÙNG 1 port trong window
    if kind == "auth_fail":
        th = THRESHOLDS["BRUTE_FORCE"]
        cnt = _count(dq, now, th["window"], kind="auth_fail", port=dport)
        if cnt >= th["count"]:
            return ("BRUTE_FORCE", cnt)

    # (2) SYN_FLOOD: nhiều gói SYN THUẦN (không ACK) từ 1 IP trong thời gian ngắn
    thsyn = THRESHOLDS["SYN_FLOOD"]
    syn_cnt = _count(dq, now, thsyn["window"], kind="syn_pass") + \
              _count(dq, now, thsyn["window"], kind="syn_block")
    if syn_cnt >= thsyn["count"]:
        return ("SYN_FLOOD", syn_cnt)

    # (3) CONN_FLOOD (DoS): TỔNG sự kiện quá nhiều trong window
    thf = THRESHOLDS["CONN_FLOOD"]
    total = _count(dq, now, thf["window"])
    if total >= thf["count"]:
        return ("CONN_FLOOD", total)

    # (4) PORT_SCAN: chạm nhiều PORT KHÁC NHAU (dựa trên fw_block) trong window
    ths = THRESHOLDS["PORT_SCAN"]
    dp = _distinct_ports(dq, now, ths["window"], kind="fw_block")
    if dp >= ths["distinct_ports"]:
        return ("PORT_SCAN", dp)

    # (5) DDoS PHÂN TÁN: xét TỔNG toàn hệ thống
    total_g, distinct_ips = _global_record(ip, now)
    if distinct_ips >= THRESHOLDS["DDOS_SPREAD"]["distinct_ips"] and total_g >= 100:
        return ("DDOS", f"{distinct_ips} IP / {total_g} event")
    if total_g >= THRESHOLDS["DDOS_VOLUME"]["count"]:
        return ("DDOS", f"{total_g} event tong")

    return None


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 6 — TRÍCH XUẤT TÍN HIỆU TỪ 1 DÒNG SYSLOG                     ║
# ║   ('instant', dict) -> event tức thời (Suricata/VPN/DHCP)         ║
# ║   ('signal',  dict) -> tín hiệu thô, đưa vào engine ngưỡng        ║
# ║   None                -> bỏ qua (log nền / noise)                 ║
# ╚══════════════════════════════════════════════════════════════════╝

def extract_signal(raw: str):
    low = raw.lower()

    # (A) Suricata alert -> TỨC THỜI (Suricata đã tự đếm ngưỡng bên trong)
    if "[**]" in raw and RE_FLOW.search(raw):
        flow = RE_FLOW.search(raw)
        msg  = RE_MSG.search(raw).group(1) if RE_MSG.search(raw) else ""
        clz  = RE_CLASS.search(raw).group(1) if RE_CLASS.search(raw) else ""
        src, dst = flow.group(2), flow.group(4)
        attacker = pick_attacker(src, dst)
        if should_ignore(attacker):
            return None
        return ("instant", {
            "event_type": classify_suricata(msg, clz),
            "src_ip": attacker, "dst_ip": dst,
            "message": msg, "detector": "suricata",
        })

    # (B) VPN tunnel down -> TỨC THỜI (không phải attacker, chỉ audit)
    if ("openvpn" in low or "charon" in low or "ipsec" in low) and \
       any(k in low for k in ("down", "disconnect", "deleting", "tunnel closed", "link inactive")):
        ips = RE_ANY_IP.findall(raw)
        return ("instant", {
            "event_type": "VPN_TUNNEL_DOWN",
            "src_ip": ips[0] if ips else None,
            "message": raw[-200:], "detector": "vpn",
        })

    # (C) DHCP thiết bị mới -> TỨC THỜI (không phải attacker, chỉ audit)
    if "dhcp" in low and ("dhcpack" in low or "new lease" in low) and RE_MAC.search(raw):
        ips = RE_ANY_IP.findall(raw)
        return ("instant", {
            "event_type": "NEW_MAC",
            "src_ip": ips[0] if ips else None,
            "message": RE_MAC.search(raw).group(1), "detector": "dhcp",
        })

    # (D) Auth log SSH thất bại -> TÍN HIỆU cho engine ngưỡng (brute force)
    m = RE_SSH_FAIL.search(raw) or RE_SSH_INVALID.search(raw)
    if m and ("failed password" in low or "invalid user" in low):
        groups = m.groups()
        ip = groups[1]
        if should_ignore(ip) or is_internal(ip):
            return None
        return ("signal", {"kind": "auth_fail", "src_ip": ip,
                           "dst_port": 22, "detector": "authlog"})

    # (E) Firewall log (filterlog) -> TÍN HIỆU cho engine ngưỡng (scan/flood/SYN flood)
    #     Xét CẢ "pass" lẫn "block" (xem lý do ở comment RE_FW_ACTION phía trên).
    if "filterlog" in raw:
        action_m = RE_FW_ACTION.search(raw)
        action = action_m.group(1) if action_m else None
        if action not in ("pass", "block"):
            return None

        ips = RE_ANY_IP.findall(raw)
        if len(ips) < 2:
            return None
        src, dst = ips[0], ips[1]
        attacker = pick_attacker(src, dst)
        if is_internal(attacker) or should_ignore(attacker):
            return None

        dport, flags = None, None
        tcp_m = RE_FILTERLOG_TCP.search(raw)
        if tcp_m:
            dport = int(tcp_m.group(4))
            flags = tcp_m.group(5)
        else:
            mm = RE_FILTERLOG_PORTS.search(raw)
            if mm:
                try:
                    dport = int(mm.group(4))
                except ValueError:
                    dport = None

        if flags == "S":
            kind = "syn_pass" if action == "pass" else "syn_block"
        else:
            kind = "fw_pass" if action == "pass" else "fw_block"

        return ("signal", {"kind": kind, "src_ip": attacker,
                           "dst_ip": dst, "dst_port": dport,
                           "detector": "filterlog"})

    return None   # log nền / noise -> bỏ qua


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 7 — XỬ LÝ FILE: ĐỌC, PHÁT HIỆN, BAN, DI CHUYỂN VÀO BKLOG      ║
# ╚══════════════════════════════════════════════════════════════════╝

def _parse_line(line: str):
    """Tách timestamp (ISO8601 do pf_collector.py ghi) + nội dung raw.
    Nếu dòng không có TAB (log cũ/định dạng khác) -> fallback dùng thời
    điểm xử lý hiện tại làm 'now'."""
    line = line.rstrip("\n")
    if not line:
        return None, None
    if "\t" in line:
        ts_str, raw = line.split("\t", 1)
        try:
            now = datetime.fromisoformat(ts_str).timestamp()
        except ValueError:
            now = time.time()
    else:
        raw, now = line, time.time()
    return now, raw


def process_line(now: float, raw: str):
    """Xử lý 1 dòng: trích tín hiệu -> (nếu vượt ngưỡng) ban IP vào đúng file."""
    result = extract_signal(raw)
    if result is None:
        return
    mode, sig = result

    if mode == "instant":
        event_type = sig["event_type"]
        logger.info(json.dumps({"mode": "instant", **sig, "processed_at": now},
                               ensure_ascii=False))
        if event_type in BAN_FILE_MAP:   # chỉ BRUTE_FORCE/PORT_SCAN/CONN_FLOOD 
            ban_ip(sig.get("src_ip"), event_type)

    elif mode == "signal":
        hit = record_and_detect(sig["src_ip"], sig.get("dst_port"), sig["kind"], now=now)
        if hit:
            event_type, metric = hit
            logger.info(json.dumps({
                "mode": "detect", "event_type": event_type, "src_ip": sig["src_ip"],
                "metric": metric, "processed_at": now}, ensure_ascii=False))
            ban_ip(sig["src_ip"], event_type)


def process_file(path: str):
    """Đọc toàn bộ 1 file pfsense_*.log, xử lý từng dòng, rồi chuyển file
    đó vào BKLOG/ để lưu trữ (không xóa)."""
    print(f"[analyzer] dang xu ly {os.path.basename(path)} ...")
    n_lines = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            now, raw = _parse_line(line)
            if raw is None:
                continue
            process_line(now, raw)
            n_lines += 1
    print(f"[analyzer] xong {os.path.basename(path)} ({n_lines} dong)")

    os.makedirs(BKLOG_DIR, exist_ok=True)
    dest = os.path.join(BKLOG_DIR, os.path.basename(path))
    shutil.move(path, dest)
    print(f"[analyzer] da chuyen vao {dest}")


def scan_and_process():
    """Quét LOG_DIR tìm các file ĐÃ ĐÓNG (pfsense_*.log), xử lý theo thứ tự
    thời gian (tên file có timestamp -> sort tên = sort theo thời gian).
    KHÔNG BAO GIỜ đụng vào file active (pfsense.log)."""
    pattern = os.path.join(LOG_DIR, FILE_PATTERN)
    for path in sorted(glob.glob(pattern)):
        if os.path.basename(path) == ACTIVE_LOG_NAME:
            continue   # an toàn kép, dù pattern đã loại trừ tên này
        process_file(path)


# ╔══════════════════════════════════════════════════════════════════╗
# ║ PHẦN 8 — VÒNG LẶP CHÍNH                                           ║
# ╚══════════════════════════════════════════════════════════════════╝

def main():
    os.makedirs(BKLOG_DIR, exist_ok=True)
    print(f"[analyzer] theo doi {os.path.join(LOG_DIR, FILE_PATTERN)} moi {POLL_INTERVAL}s")
    print(f"[analyzer] file ban: {BAN_SCANPORT} / {BAN_BRUTEFORCE} / {BAN_DDOS}")
    print(f"[analyzer] da co san: scanport={len(_banned[BAN_SCANPORT])} "
          f"bruteforce={len(_banned[BAN_BRUTEFORCE])} ddos={len(_banned[BAN_DDOS])}\n")
    while True:
        scan_and_process()
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
