#!/usr/bin/env python3
"""
pfSense Syslog -> n8n Webhook Forwarder
----------------------------------------
Nghe syslog UDP tu pfSense, parse, chuan hoa thanh JSON dung format
ma WF-00 (Code node) dang doi, roi POST sang Production URL cua n8n.

Chi dung thu vien chuan -> khong can pip install.
Chay duoc tren ca Linux va Windows (can Python 3.7+).
"""

import socket
import json
import re
import urllib.request
from datetime import datetime, timezone

# ===================== CAU HINH =====================
LISTEN_IP   = "0.0.0.0"          # nghe tren moi interface cua VM n8n
LISTEN_PORT = 5514               # >1024 nen khong can quyen root tren Linux
N8N_WEBHOOK = "http://127.0.0.1:5678/webhook/pfsense-event"  # Production URL cua WF-00
SITE        = "HCM-01"           # ten site, gan vao moi event
DEBUG_FORWARD_ALL = False        # True = forward ca log khong nhan dien duoc (de debug)
# ====================================================

# --- Regex cho Suricata fast.log ---
RE_PRIORITY = re.compile(r"\[Priority:\s*(\d+)\]")
RE_MSG      = re.compile(r"\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]")
RE_CLASS    = re.compile(r"\[Classification:\s*(.*?)\]")
RE_FLOW     = re.compile(r"\{(\w+)\}\s+([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)")
# --- Regex tien ich ---
RE_ANY_IP   = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
RE_MAC      = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")


def severity_from_priority(prio: str) -> str:
    return {"1": "HIGH", "2": "MEDIUM", "3": "LOW"}.get(prio, "MEDIUM")


def classify_suricata(msg: str, classification: str) -> str:
    """Map alert Suricata -> event_type ma WF-00 hieu."""
    text = (msg + " " + classification).lower()
    if "brute" in text or "ssh scan" in text:
        return "BRUTE_FORCE"
    if "scan" in text or "information leak" in text:
        return "PORT_SCAN"
    return "IDS_ALERT"


def parse_line(raw: str):
    """Tra ve dict da chuan hoa, hoac None neu khong nhan dien duoc."""
    low = raw.lower()

    # 1) Suricata fast.log
    if "[**]" in raw and RE_FLOW.search(raw):
        flow = RE_FLOW.search(raw)
        prio = (RE_PRIORITY.search(raw) or [None, "2"])[1] if RE_PRIORITY.search(raw) else "2"
        msg  = RE_MSG.search(raw).group(1) if RE_MSG.search(raw) else ""
        clz  = RE_CLASS.search(raw).group(1) if RE_CLASS.search(raw) else ""
        return {
            "event_type": classify_suricata(msg, clz),
            "src_ip": flow.group(2),
            "dst_ip": flow.group(4),
            "protocol": flow.group(1),
            "severity": severity_from_priority(prio),
            "message": msg,
        }

    # 2) VPN tunnel down (OpenVPN / IPsec)
    if ("openvpn" in low or "charon" in low or "ipsec" in low) and \
       any(k in low for k in ("down", "disconnect", "deleting", "tunnel closed", "link inactive")):
        ips = RE_ANY_IP.findall(raw)
        return {
            "event_type": "VPN_TUNNEL_DOWN",
            "src_ip": ips[0] if ips else None,
            "dst_ip": None,
            "protocol": "VPN",
            "severity": "HIGH",
            "message": raw[-200:],
        }

    # 3) Thiet bi moi (DHCP cap lease moi)
    if "dhcp" in low and ("dhcpack" in low or "new lease" in low) and RE_MAC.search(raw):
        ips = RE_ANY_IP.findall(raw)
        return {
            "event_type": "NEW_MAC",
            "src_ip": ips[0] if ips else None,
            "dst_ip": None,
            "protocol": "DHCP",
            "severity": "LOW",
            "message": RE_MAC.search(raw).group(1),
        }

    # 4) Khong nhan dien -> tuy chon forward de debug
    if DEBUG_FORWARD_ALL:
        return {
            "event_type": "UNKNOWN",
            "src_ip": (RE_ANY_IP.findall(raw) or [None])[0],
            "dst_ip": None,
            "protocol": None,
            "severity": "LOW",
            "message": raw[-200:],
        }
    return None


def post_to_n8n(payload: dict):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        N8N_WEBHOOK, data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"  -> n8n {resp.status} | {payload['event_type']} | src={payload.get('src_ip')}")
    except Exception as e:
        print(f"  !! POST that bai: {e}")


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[forwarder] dang nghe syslog UDP {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[forwarder] forward toi {N8N_WEBHOOK}\n")

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
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {addr[0]} -> {parsed['event_type']}")
        post_to_n8n(parsed)


if __name__ == "__main__":
    main()
