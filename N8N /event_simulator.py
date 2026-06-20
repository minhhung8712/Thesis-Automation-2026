#!/usr/bin/env python3
"""
Event Simulator cho he thong n8n
--------------------------------------
Ban loat event gia vao webhook WF-00 de test toan bo cac nhanh
ma KHONG can pfSense hay forwarder. Chay: python event_simulator.py
"""
import json
import time
import urllib.request

# Production URL cua WF-00 (workflow phai dang Active)
WEBHOOK = "http://127.0.0.1:5678/webhook/pfsense-event"
DELAY = 1.0  # giay nghi giua cac event

# Moi event kem nhanh KY VONG de Khai doi chieu trong Executions
EVENTS = [
    ("WF-01 / AUTO_BLOCK",   {"event_type": "IDS_ALERT", "src_ip": "203.0.113.45", "severity": "HIGH", "site": "HCM-01"}),
    ("WF-01 / NEEDS_APPROVAL",{"event_type": "BRUTE_FORCE", "src_ip": "198.51.100.7", "severity": "MEDIUM", "site": "HCM-01"}),
    ("WF-01 / WHITELISTED",  {"event_type": "PORT_SCAN", "src_ip": "192.168.10.30", "severity": "MEDIUM"}),
    ("WF-01 / MONITOR",      {"event_type": "PORT_SCAN", "src_ip": "45.33.12.9", "severity": "MEDIUM"}),
    ("WF-02 / CRITICAL",     {"event_type": "HIGH_BANDWIDTH", "src_ip": "203.0.113.9", "current_mbps": 350, "site": "HCM-01"}),
    ("WF-02 / ANOMALY",      {"event_type": "CONN_FLOOD", "src_ip": "203.0.113.9", "current_mbps": 200, "site": "HCM-01"}),
    ("WF-03 / UNKNOWN",      {"event_type": "NEW_MAC", "mac": "11:22:33:44:55:66", "src_ip": "192.168.10.104"}),
    ("WF-03 / KNOWN",        {"event_type": "NEW_MAC", "mac": "aa:bb:cc:dd:ee:ff", "src_ip": "192.168.10.50"}),
    ("WF-04 / TIMEOUT_FLAP", {"event_type": "VPN_TUNNEL_DOWN", "site": "Site-B", "raw": {"message": "link inactive timeout"}}),
    ("WF-04 / AUTH_CONFIG",  {"event_type": "VPN_TUNNEL_DOWN", "site": "Site-C", "raw": {"message": "auth failed bad credential"}}),
    ("WF-Discard",           {"event_type": "SOMETHING_WEIRD", "src_ip": "10.0.0.1"}),
]

def send(payload):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(WEBHOOK, data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status

def main():
    print(f"Ban {len(EVENTS)} event toi {WEBHOOK}\n")
    ok = 0
    for label, payload in EVENTS:
        try:
            status = send(payload)
            mark = "OK " if status == 200 else f"({status})"
            print(f"  {mark} {label:24s} <- {payload['event_type']}")
            if status == 200:
                ok += 1
        except Exception as e:
            print(f"  !! {label:24s} loi: {e}")
        time.sleep(DELAY)
    print(f"\nXong: {ok}/{len(EVENTS)} gui thanh cong. Mo tab Executions cua WF-00 de xem chi tiet.")

if __name__ == "__main__":
    main()
