#!/usr/bin/env python3
"""
pfSense Syslog -> n8n Webhook Forwarder (v2)
=============================================
Nghe syslog UDP tu pfSense (192.168.10.1), parse, chuan hoa thanh JSON
theo dinh dang WF-00 mong doi, roi POST sang webhook n8n (192.168.10.2).

NANG CAP so voi v1:
  1. Ghi log rotating: luu cac event DA forward ra file (backup + forensics).
  2. Nhan dien IP attacker (dai WAN/LAN cua lab) va phan biet noi-bo vs ngoai.
  3. Parse them FILTERLOG (firewall block) - nguon tin hieu chinh khi
     Suricata chua bat, khop voi Floating Rule + alias N8N_BLOCKLIST cua ban A.

Chi dung thu vien chuan -> khong can pip install. Python 3.7+.
"""

import socket
import json
import re
import logging
import urllib.request
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

# ===================== CAU HINH =====================
LISTEN_IP    = "0.0.0.0"       # nghe tren moi interface cua VM n8n (192.168.10.2)
LISTEN_PORT  = 514             # khop voi Remote Logging pfSense (192.168.10.2:514)
N8N_WEBHOOK  = "http://127.0.0.1:5678/webhook/pfsense-event"
SITE         = "HCM-01"
DEBUG_FORWARD_ALL = False      # True = forward ca log khong nhan dien (chi de debug)

# Dai mang noi bo (KHONG coi la attacker du co xuat hien trong log)
INTERNAL_NETS = ["192.168.10.", "192.168.11.", "192.168.12.", "192.168.20."]

# File log luu cac event da forward (rotating)
LOG_FILE       = "forwarded_events.log"
LOG_MAX_BYTES  = 10 * 1024 * 1024   # 10 MB moi file
LOG_BACKUP     = 5                  # giu 5 file gan nhat
# ====================================================

# --- Logger ghi ra file rotating ---
logger = logging.getLogger("forwarder")
logger.setLevel(logging.INFO)
_fh = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger.addHandler(_fh)

# --- Regex ---
RE_PRIORITY = re.compile(r"\[Priority:\s*(\d+)\]")
RE_MSG      = re.compile(r"\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]")
RE_CLASS    = re.compile(r"\[Classification:\s*(.*?)\]")
RE_FLOW     = re.compile(r"\{(\w+)\}\s+([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)")
RE_ANY_IP   = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
RE_MAC      = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")


def severity_from_priority(prio: str) -> str:
    return {"1": "HIGH", "2": "MEDIUM", "3": "LOW"}.get(prio, "MEDIUM")


def is_internal(ip: str) -> bool:
    return bool(ip) and any(ip.startswith(net) for net in INTERNAL_NETS)


def pick_attacker(src: str, dst: str):
    """Xac dinh dau la attacker: uu tien IP KHONG thuoc mang noi bo."""
    if src and not is_internal(src):
        return src
    if dst and not is_internal(dst):
        return dst
    return src or dst


def classify_suricata(msg: str, classification: str) -> str:
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
    Parse dong filterlog cua pfSense (firewall block/pass).
    Format CSV: rule,sub,anchor,tracker,iface,reason,action,dir,ipver,...,proto,...,src,dst,sport,dport
    Chi quan tam khi action=block. Lay src/dst IP tu cac token IP trong dong.
    """
    if "filterlog" not in raw:
        return None
    # Chi xu ly cac goi bi CHAN
    if ",block," not in raw and ",block" not in raw:
        return None
    ips = RE_ANY_IP.findall(raw)
    if len(ips) < 2:
        return None
    src, dst = ips[0], ips[1]
    attacker = pick_attacker(src, dst)
    # Neu attacker la noi bo het -> khong dang ke, bo qua
    if is_internal(attacker):
        return None
    return {
        "event_type": "PORT_SCAN",       # firewall chan lien tuc 1 IP -> nghi scan
        "src_ip": attacker,
        "dst_ip": dst if attacker == src else src,
        "protocol": "tcp" if ",tcp," in raw.lower() else None,
        "severity": "MEDIUM",
        "message": "firewall block (filterlog)",
        "detector": "filterlog",
    }


def parse_line(raw: str):
    low = raw.lower()

    # 1) Suricata fast.log (uu tien cao nhat - IDS da phan tich)
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

    # 2) VPN tunnel down
    if ("openvpn" in low or "charon" in low or "ipsec" in low) and \
       any(k in low for k in ("down", "disconnect", "deleting", "tunnel closed", "link inactive")):
        ips = RE_ANY_IP.findall(raw)
        return {
            "event_type": "VPN_TUNNEL_DOWN",
            "src_ip": ips[0] if ips else None,
            "dst_ip": None, "protocol": "VPN", "severity": "HIGH",
            "message": raw[-200:], "detector": "vpn",
        }

    # 3) Thiet bi moi (DHCP)
    if "dhcp" in low and ("dhcpack" in low or "new lease" in low) and RE_MAC.search(raw):
        ips = RE_ANY_IP.findall(raw)
        return {
            "event_type": "NEW_MAC",
            "src_ip": ips[0] if ips else None,
            "dst_ip": None, "protocol": "DHCP", "severity": "LOW",
            "message": RE_MAC.search(raw).group(1), "detector": "dhcp",
        }

    # 4) Firewall block (filterlog) - nguon chinh khi chua co Suricata
    fw = parse_filterlog(raw)
    if fw:
        return fw

    # 5) Khong nhan dien -> tuy chon debug
    if DEBUG_FORWARD_ALL:
        return {
            "event_type": "UNKNOWN",
            "src_ip": (RE_ANY_IP.findall(raw) or [None])[0],
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


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[forwarder v2] nghe syslog UDP {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[forwarder v2] forward toi {N8N_WEBHOOK}")
    print(f"[forwarder v2] ghi log vao {LOG_FILE} (rotating {LOG_BACKUP}x{LOG_MAX_BYTES//1024//1024}MB)\n")

    while True:
        data, addr = sock.recvfrom(8192)
        raw = data.decode("utf-8", errors="replace").strip()
        parsed = parse_line(raw)
        if not parsed:
            continue

        parsed.update({
            "event_id": f"evt-{int(datetime.now().timestamp()*1000)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "site": SITE,
            "source_host": addr[0],
        })

        print(f"[{datetime.now().strftime('%H:%M:%S')}] {addr[0]} -> "
              f"{parsed['event_type']} (src={parsed.get('src_ip')}, by={parsed.get('detector')})")

        status = post_to_n8n(parsed)
        # Ghi log rotating: chi ghi event da forward (khong ghi noise)
        logger.info(json.dumps({**parsed, "n8n_status": status}, ensure_ascii=False))


if __name__ == "__main__":
    main()
