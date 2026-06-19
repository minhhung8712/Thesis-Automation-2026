#!/usr/bin/env python3
"""
Event Simulator chuyen biet cho WF-01 (IP Attack Handler v2)
-------------------------------------------------------------
Ban du 6 case de phu het 4 nhanh: WHITELISTED / AUTO_BLOCK / NEEDS_APPROVAL / MONITOR.

LUU Y khi test KHONG co pfSense that:
  - Node "Get pfSense Whitelist" (HTTP GET 192.168.10.1) se timeout/fail.
  - Hay DISABLE node do trong n8n (chuot phai -> Disable), HOAC pin du lieu mock.
  - Code node co try/catch fallback whitelist = ['192.168.10.1','192.168.10.2','192.168.10.30'].
    Nhung neu node HTTP bao loi do (stop), Code node se khong chay. Disable la chac an nhat.

Cay quyet dinh (doc tu code that):
  whitelisted?            -> WHITELISTED
  BRUTE_FORCE             -> HIGH  -> AUTO_BLOCK
  IDS_ALERT + sev=HIGH    -> HIGH  -> AUTO_BLOCK
  PORT_SCAN               -> MEDIUM-> NEEDS_APPROVAL
  con lai (sev=LOW/rong)  -> LOW   -> MONITOR
"""
import json
import time
import urllib.request

WEBHOOK = "http://127.0.0.1:5678/webhook/pfsense-event"
DELAY = 1.0

# Gia dinh whitelist chua 192.168.10.30 (co trong fallback list cua Code node).
EVENTS = [
    ("WF-01 / WHITELISTED",
     {"event_type": "PORT_SCAN", "src_ip": "192.168.10.30", "severity": "MEDIUM", "site": "HCM-01"}),

    ("WF-01 / AUTO_BLOCK (IDS HIGH)",
     {"event_type": "IDS_ALERT", "src_ip": "203.0.113.45", "severity": "HIGH", "site": "HCM-01"}),

    ("WF-01 / AUTO_BLOCK (BRUTE)",
     {"event_type": "BRUTE_FORCE", "src_ip": "198.51.100.7", "site": "HCM-01"}),

    ("WF-01 / NEEDS_APPROVAL",
     {"event_type": "PORT_SCAN", "src_ip": "45.33.12.9", "site": "HCM-01"}),

    ("WF-01 / MONITOR (IDS LOW)",
     {"event_type": "IDS_ALERT", "src_ip": "45.33.12.50", "severity": "LOW", "site": "HCM-01"}),

    ("WF-01 / MONITOR (unknown)",
     {"event_type": "SUSPICIOUS_TRAFFIC", "src_ip": "45.33.12.51", "site": "HCM-01"}),
]


def send(payload):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(WEBHOOK, data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status


def main():
    print(f"Ban {len(EVENTS)} event WF-01 toi {WEBHOOK}\n")
    ok = 0
    for label, payload in EVENTS:
        try:
            status = send(payload)
            mark = "OK " if status == 200 else f"({status})"
            print(f"  {mark} {label:30s} <- {payload['event_type']:20s} src={payload['src_ip']}")
            if status == 200:
                ok += 1
        except Exception as e:
            print(f"  !! {label:30s} loi: {e}")
        time.sleep(DELAY)
    print(f"\nXong: {ok}/{len(EVENTS)} gui thanh cong. Mo Executions cua WF-00 va WF-01 de doi chieu nhanh.")


if __name__ == "__main__":
    main()
