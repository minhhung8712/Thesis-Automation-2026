#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
forwarder.py - CAU NOI SYSLOG (pfSense) -> n8n  [BAN NGUONG / THRESHOLD]
Phat hien theo NGUONG HANH VI (sliding window), khong doan tu 1 dong don le.
"""
import socket, json, re, time, logging, urllib.request
from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

# ===== CAU HINH =====
LISTEN_IP="0.0.0.0"; LISTEN_PORT=514
N8N_WEBHOOK="http://127.0.0.1:5678/webhook/pfsense-event"; SITE="HCM-01"
PFSENSE_IP="192.168.10.1"; ONLY_ACCEPT_FROM_PFSENSE=False; DEBUG_FORWARD_ALL=False
INTERNAL_NETS=["192.168.10.","192.168.11.","192.168.12.","192.168.20."]
IGNORE_PREFIXES=["169.254.","224.","239.","255.","0.","127."]
IGNORE_EXACT=["192.168.183.1","192.168.10.1"]

THRESHOLDS={
    "BRUTE_FORCE":{"count":5,"window":60},
    "PORT_SCAN":{"distinct_ports":15,"window":10},
    "CONN_FLOOD":{"count":100,"window":10},
}
COOLDOWN=300; MAX_TRACKED_IPS=5000
LOG_FILE="forwarded_events.log"; LOG_MAX_BYTES=10*1024*1024; LOG_BACKUP=5

logger=logging.getLogger("forwarder"); logger.setLevel(logging.INFO)
_fh=RotatingFileHandler(LOG_FILE,maxBytes=LOG_MAX_BYTES,backupCount=LOG_BACKUP,encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s %(message)s")); logger.addHandler(_fh)

RE_PRIORITY=re.compile(r"\[Priority:\s*(\d+)\]")
RE_MSG=re.compile(r"\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]")
RE_CLASS=re.compile(r"\[Classification:\s*(.*?)\]")
RE_FLOW=re.compile(r"\{(\w+)\}\s+([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)")
RE_ANY_IP=re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
RE_MAC=re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
RE_FILTERLOG_PORTS=re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}),(\d{1,3}(?:\.\d{1,3}){3}),(\d+),(\d+)")
RE_SSH_FAIL=re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)")
RE_SSH_INVALID=re.compile(r"Invalid user (\S+) from ([\d.]+)")

def severity_from_priority(p): return {"1":"HIGH","2":"MEDIUM","3":"LOW"}.get(p,"MEDIUM")
def is_internal(ip): return bool(ip) and any(ip.startswith(n) for n in INTERNAL_NETS)
def should_ignore(ip):
    if not ip: return True
    if ip in IGNORE_EXACT: return True
    return any(ip.startswith(p) for p in IGNORE_PREFIXES)
def pick_attacker(src,dst):
    if src and not is_internal(src): return src
    if dst and not is_internal(dst): return dst
    return src or dst
def classify_suricata(msg,clz):
    t=(msg+" "+clz).lower()
    if "brute" in t or "ssh scan" in t or "login" in t: return "BRUTE_FORCE"
    if "scan" in t or "information leak" in t: return "PORT_SCAN"
    if "dos" in t or "flood" in t: return "CONN_FLOOD"
    return "IDS_ALERT"

# ===== ENGINE NGUONG =====
_events=defaultdict(deque); _last_alert={}; _MAX_WINDOW=60
def _trim(dq,now):
    c=now-_MAX_WINDOW
    while dq and dq[0][0]<c: dq.popleft()
def _count(dq,now,window,kind=None,port=None):
    c=now-window; n=0
    for ts,p,k in dq:
        if ts<c: continue
        if kind and k!=kind: continue
        if port is not None and p!=port: continue
        n+=1
    return n
def _distinct_ports(dq,now,window,kind=None):
    c=now-window; s=set()
    for ts,p,k in dq:
        if ts>=c and (kind is None or k==kind) and p is not None: s.add(p)
    return len(s)
def record_and_detect(ip,dport,kind,now=None):
    if now is None: now=time.time()
    if len(_events)>MAX_TRACKED_IPS:
        for k in list(_events.keys()):
            _trim(_events[k],now)
            if not _events[k]: del _events[k]
    dq=_events[ip]; dq.append((now,dport,kind)); _trim(dq,now)
    if kind=="auth_fail":
        th=THRESHOLDS["BRUTE_FORCE"]
        cnt=_count(dq,now,th["window"],kind="auth_fail",port=dport)
        if cnt>=th["count"]: return ("BRUTE_FORCE",cnt)
    thf=THRESHOLDS["CONN_FLOOD"]
    tot=_count(dq,now,thf["window"])
    if tot>=thf["count"]: return ("CONN_FLOOD",tot)
    ths=THRESHOLDS["PORT_SCAN"]
    dp=_distinct_ports(dq,now,ths["window"],kind="fw_block")
    if dp>=ths["distinct_ports"]: return ("PORT_SCAN",dp)
    return None
def in_cooldown(ip,et,now=None):
    if now is None: now=time.time()
    key=(ip,et); last=_last_alert.get(key)
    if last is not None and (now-last)<COOLDOWN: return True
    _last_alert[key]=now; return False

def extract_signal(raw):
    low=raw.lower()
    if "[**]" in raw and RE_FLOW.search(raw):
        f=RE_FLOW.search(raw)
        prio=RE_PRIORITY.search(raw).group(1) if RE_PRIORITY.search(raw) else "2"
        msg=RE_MSG.search(raw).group(1) if RE_MSG.search(raw) else ""
        clz=RE_CLASS.search(raw).group(1) if RE_CLASS.search(raw) else ""
        src,dst=f.group(2),f.group(4); att=pick_attacker(src,dst)
        if should_ignore(att): return None
        return ("instant",{"event_type":classify_suricata(msg,clz),"src_ip":att,"dst_ip":dst,
            "dst_port":int(f.group(5)) if f.group(5).isdigit() else None,"protocol":f.group(1),
            "severity":severity_from_priority(prio),"message":msg,"detector":"suricata"})
    if ("openvpn" in low or "charon" in low or "ipsec" in low) and any(k in low for k in ("down","disconnect","deleting","tunnel closed","link inactive")):
        ips=RE_ANY_IP.findall(raw)
        return ("instant",{"event_type":"VPN_TUNNEL_DOWN","src_ip":ips[0] if ips else None,"dst_ip":None,"protocol":"VPN","severity":"HIGH","message":raw[-200:],"detector":"vpn"})
    if "dhcp" in low and ("dhcpack" in low or "new lease" in low) and RE_MAC.search(raw):
        ips=RE_ANY_IP.findall(raw)
        return ("instant",{"event_type":"NEW_MAC","src_ip":ips[0] if ips else None,"dst_ip":None,"protocol":"DHCP","severity":"LOW","message":RE_MAC.search(raw).group(1),"detector":"dhcp"})
    m=RE_SSH_FAIL.search(raw) or RE_SSH_INVALID.search(raw)
    if m and ("failed password" in low or "invalid user" in low):
        g=m.groups(); ip=g[1]
        if should_ignore(ip) or is_internal(ip): return None
        return ("signal",{"kind":"auth_fail","src_ip":ip,"dst_port":22,"detector":"authlog"})
    if "filterlog" in raw and "block" in low:
        ips=RE_ANY_IP.findall(raw)
        if len(ips)>=2:
            src,dst=ips[0],ips[1]; att=pick_attacker(src,dst)
            if is_internal(att) or should_ignore(att): return None
            dport=None; mm=RE_FILTERLOG_PORTS.search(raw)
            if mm:
                try: dport=int(mm.group(4))
                except ValueError: dport=None
            return ("signal",{"kind":"fw_block","src_ip":att,"dst_ip":dst,"dst_port":dport,"detector":"filterlog"})
    if DEBUG_FORWARD_ALL:
        return ("instant",{"event_type":"UNKNOWN","src_ip":(RE_ANY_IP.findall(raw) or [None])[0],"dst_ip":None,"protocol":None,"severity":"LOW","message":raw[-200:],"detector":"debug"})
    return None

def build_detection_event(et,sig,metric):
    th=THRESHOLDS.get(et,{}); win=th.get("window","?")
    sev="HIGH" if et in ("BRUTE_FORCE","CONN_FLOOD") else "MEDIUM"
    detail={"BRUTE_FORCE":f"{metric} lan dang nhap sai trong {win}s",
            "PORT_SCAN":f"cham {metric} port khac nhau trong {win}s",
            "CONN_FLOOD":f"{metric} ket noi trong {win}s"}.get(et,f"metric={metric}")
    return {"event_type":et,"src_ip":sig["src_ip"],"dst_ip":sig.get("dst_ip"),
            "dst_port":sig.get("dst_port"),"severity":sev,"metric":metric,"threshold":th,
            "message":f"Nguong vuot: {detail}","detector":sig.get("detector")}

def post_to_n8n(payload):
    body=json.dumps(payload).encode("utf-8")
    req=urllib.request.Request(N8N_WEBHOOK,data=body,headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=5) as r:
            print(f"  -> n8n {r.status} | {payload['event_type']} | src={payload.get('src_ip')}")
            return r.status
    except Exception as e:
        print(f"  !! POST that bai: {e}"); return None

def emit(ev,sender_ip):
    ev.update({"event_id":f"evt-{int(time.time()*1000)}","timestamp":datetime.now(timezone.utc).isoformat(),"site":SITE,"source_host":sender_ip})
    print(f"[{datetime.now().strftime('%H:%M:%S')}] tu {sender_ip} -> {ev['event_type']} (src={ev.get('src_ip')}, port={ev.get('dst_port')}, by={ev.get('detector')}, metric={ev.get('metric','-')})")
    st=post_to_n8n(ev); logger.info(json.dumps({**ev,"n8n_status":st},ensure_ascii=False))

def main():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((LISTEN_IP,LISTEN_PORT))
    print(f"[forwarder] nghe syslog UDP {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[forwarder] NGUONG brute={THRESHOLDS['BRUTE_FORCE']} scan={THRESHOLDS['PORT_SCAN']} flood={THRESHOLDS['CONN_FLOOD']}")
    print(f"[forwarder] cooldown={COOLDOWN}s | forward toi {N8N_WEBHOOK}\n")
    while True:
        data,addr=s.recvfrom(8192); sender_ip=addr[0]
        if ONLY_ACCEPT_FROM_PFSENSE and sender_ip!=PFSENSE_IP: continue
        raw=data.decode("utf-8",errors="replace").strip()
        r=extract_signal(raw)
        if r is None: continue
        mode,d=r
        if mode=="instant": emit(d,sender_ip)
        elif mode=="signal":
            hit=record_and_detect(d["src_ip"],d.get("dst_port"),d["kind"])
            if hit:
                et,mt=hit
                if not in_cooldown(d["src_ip"],et): emit(build_detection_event(et,d,mt),sender_ip)

if __name__=="__main__": main()
