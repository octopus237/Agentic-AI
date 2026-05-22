"""
correlate.py -- Wazuh Correlation Agent
Run: python3 correlate.py [--severity N] [--hours N] [--agent ID] [--debug]
"""
import os, sys, json, argparse, requests, urllib3, logging, time
from pathlib import Path
from datetime import datetime, timezone, timedelta
import ollama

urllib3.disable_warnings()

# -- Config --------------------------------------------------------------------
def _env(p=".env"):
    if Path(p).exists():
        for line in Path(p).read_text().splitlines():
            if line.strip() and "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
_env()

C = {
    "HOST":    os.getenv("WAZUH_HOST",    "https://localhost:55000"),
    "USER":    os.getenv("WAZUH_USER",    "wazuh-agent"),
    "PASSWD":  os.getenv("WAZUH_PASS",    "wazuh"),
    "IX_HOST": os.getenv("INDEXER_HOST",  "https://localhost:9200"),
    "IX_USER": os.getenv("INDEXER_USER",  "admin"),
    "IX_PASS": os.getenv("INDEXER_PASS",  "admin"),
    "MODEL":   os.getenv("OLLAMA_MODEL",  "qwen2.5:3b"),
    "OL_HOST": os.getenv("OLLAMA_HOST",   "http://localhost:11434"),
}
SSL     = os.getenv("WAZUH_SSL","false").lower() == "true"
MIN_SEV = int(os.getenv("MIN_SEVERITY","3"))
HOURS   = int(os.getenv("LOOK_BACK_HOURS","24"))

# -- Logger --------------------------------------------------------------------
def _setup_logger(debug=False):
    log = logging.getLogger("correlate")
    log.setLevel(logging.DEBUG if debug else logging.WARNING)
    log.handlers.clear()
    fmt = logging.Formatter("%(asctime)s.%(msecs)03d  %(message)s", datefmt="%H:%M:%S")
    sh  = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.DEBUG if debug else logging.WARNING)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    if debug:
        fh = logging.FileHandler("correlate.log", mode="a")
        fh.setLevel(logging.DEBUG); fh.setFormatter(fmt)
        log.addHandler(fh)
    return log

log = _setup_logger()
_tok, _tok_exp = None, 0
def _now():    return datetime.now(timezone.utc)
def _since(h): return (_now()-timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")
NL = "\n"

# -- API helpers ---------------------------------------------------------------
def _auth():
    global _tok, _tok_exp
    if not _tok or time.time() >= _tok_exp-60:
        r = requests.post(f"{C['HOST']}/security/user/authenticate",
                          auth=(C['USER'],C['PASSWD']), verify=SSL, timeout=10)
        r.raise_for_status()
        _tok, _tok_exp = r.json()["data"]["token"], time.time()+890
    return {"Authorization": f"Bearer {_tok}"}

def wget(path, params=None):
    t0 = time.perf_counter()
    try:
        r = requests.get(f"{C['HOST']}{path}", headers=_auth(),
                         params=params, verify=SSL, timeout=15)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Cannot reach Wazuh at {C['HOST']}")
    except requests.exceptions.Timeout:
        raise RuntimeError(f"Wazuh timeout on {path}")
    ms = int((time.perf_counter()-t0)*1000)
    if r.status_code in (400,404):
        log.debug("GET %s -> %d", path, r.status_code)
        return {"affected_items":[],"total_affected_items":0,f"_{r.status_code}":True}
    if r.status_code == 401: raise RuntimeError(f"401 {path} -- check token/permissions")
    if r.status_code == 403: raise RuntimeError(f"403 {path} -- add permission to policy")
    r.raise_for_status()
    log.debug("GET %s -> %dms", path, ms)
    return r.json().get("data",{})

def _ix_post(body, index="wazuh-alerts-*"):
    try:
        r = requests.post(f"{C['IX_HOST']}/{index}/_search",
                          auth=(C['IX_USER'],C['IX_PASS']),
                          json=body, verify=SSL, timeout=20)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Cannot reach indexer at {C['IX_HOST']}")
    if r.status_code == 401: raise RuntimeError("Indexer 401 -- check credentials")
    if r.status_code == 403: raise RuntimeError("Indexer 403 -- missing cluster_composite_ops_ro")
    if r.status_code == 404: return None
    r.raise_for_status()
    return r.json()

def ix_search(q, size=30, sort=None, index="wazuh-alerts-*"):
    body = {"size":size,"query":q}
    if sort: body["sort"]=sort
    t0 = time.perf_counter()
    res = _ix_post(body, index)
    if not res: return {"total":0,"hits":[]}
    hits = res["hits"]
    log.debug("SEARCH -> %dms hits=%d", int((time.perf_counter()-t0)*1000),
              hits["total"]["value"])
    return {"total":hits["total"]["value"],"hits":[h["_source"] for h in hits["hits"]]}

def ix_agg(q, aggs):
    t0 = time.perf_counter()
    res = _ix_post({"size":0,"query":q,"aggs":aggs})
    if not res: return {}
    log.debug("AGG -> %dms", int((time.perf_counter()-t0)*1000))
    return res.get("aggregations",{})

# -- Deduplication config ------------------------------------------------------
# Groups to exclude from investigation
# NOTE: "ossec" was removed — Wazuh port/netstat alerts use this group
# NOTE: "wazuh" was removed — agent start/stop events use this group
SKIP = {"sca","policy_changed","gpg_no_pubkey",
        "agent_restarting","audit_selinux","audit","syslog"}

CANONICAL = {
    "syscheck_file":"syscheck","syscheck_entry_modified":"syscheck",
    "syscheck_entry_added":"syscheck","syscheck_entry_deleted":"syscheck",
    "authentication_failed":"authentication","authentication_success":"authentication",
    "invalid_login":"authentication","pam":"authentication",
    "access_control":"authentication","win_authentication_success":"authentication",
    "windows_security":"authentication",
    "sysmon_eid1_detections":"sysmon","sysmon_eid7_detections":"sysmon",
    "sysmon_eid10_detections":"sysmon","sysmon_eid11_detections":"sysmon",
    "win_evt_channel":"windows","windows_system":"windows",
    "netstat":"network_changes",
    "ossec":"network_changes",   # Wazuh port/netstat monitoring alerts
}

# -- Fetch & deduplicate alerts ------------------------------------------------
def fetch_alerts(since, min_sev, agent_id=None):
    must = [{"range":{"rule.level":{"gte":min_sev}}},
            {"range":{"timestamp":{"gte":since}}}]
    if agent_id: must.append({"term":{"agent.id":agent_id}})
    must_not = ([{"match":{"rule.groups":g}} for g in ["sca","policy_changed"]] +
                [{"match":{"rule.description":d}} for d in ["CIS Benchmark","SCA summary"]])
    q = {"bool":{"must":must,"must_not":must_not}}

    aggs = ix_agg(q, {
        "total":   {"value_count":{"field":"rule.level"}},
        "by_group":{"terms":{"field":"rule.groups","size":25,
                             "order":{"max_lv":"desc"}},
                    "aggs":{"max_lv":   {"max":{"field":"rule.level"}},
                            "count":    {"value_count":{"field":"rule.level"}},
                            "agents":   {"terms":{"field":"agent.name","size":3}},
                            "tactics":  {"terms":{"field":"rule.mitre.tactic","size":3}},
                            "top_rules":{"terms":{"field":"rule.description","size":3}},
                            "sample":   {"top_hits":{"size":1,
                                         "sort":[{"rule.level":{"order":"desc"}}],
                                         "_source":["timestamp","agent.id","agent.name",
                                         "data.srcip","data.srcuser","full_log",
                                         "syscheck.path","rule.description"]}}}},
        "dist":{"range":{"field":"rule.level","ranges":[
            {"key":"low (3-6)",     "from":3, "to":7},
            {"key":"medium (7-9)", "from":7, "to":10},
            {"key":"high (10-12)","from":10,"to":13},
            {"key":"critical (13+)","from":13}]}}
    })

    total = aggs.get("total",{}).get("value",0)
    dist  = {b["key"]:b["doc_count"]
             for b in aggs.get("dist",{}).get("buckets",[]) if b["doc_count"]}
    raw = []
    for b in aggs.get("by_group",{}).get("buckets",[]):
        g   = CANONICAL.get(b["key"], b["key"])
        if g in SKIP: continue
        src = b.get("sample",{}).get("hits",{}).get("hits",[{}])[0].get("_source",{})
        raw.append({
            "rule":    src.get("rule",{}).get("description",g) if src else g,
            "group":   g,
            "covered": [x["key"] for x in b.get("top_rules",{}).get("buckets",[])],
            "level":   int(b.get("max_lv",{}).get("value",0)),
            "count":   int(b.get("count",{}).get("value",0)),
            "agents":  [x["key"] for x in b.get("agents",{}).get("buckets",[])],
            "agent_id":src.get("agent",{}).get("id","") if src else "",
            "tactics": [x["key"] for x in b.get("tactics",{}).get("buckets",[])],
            "ts":      src.get("timestamp","")[:19] if src else "",
            "src_ip":  src.get("data",{}).get("srcip","") if src else "",
            "src_user":src.get("data",{}).get("srcuser","") if src else "",
            "log":     src.get("full_log","")[:200] if src else "",
            "filepath":src.get("syscheck",{}).get("path","") if src else "",
        })
    merged = {}
    for a in raw:
        key = (a["group"],a["agent_id"])
        if key not in merged or a["level"] > merged[key]["level"]:
            merged[key] = a
        else:
            merged[key]["count"] += a["count"]
    return total, dist, sorted(merged.values(), key=lambda x:(-x["level"],-x["count"]))

# -- Attack chain --------------------------------------------------------------
def _event_text(e):
    return " ".join([e.get("rule",""),e.get("log",""),e.get("cmd",""),
                     e.get("image",""),e.get("parent",""),
                     e.get("target",""),e.get("regkey","")]).lower()

def get_chain(agent_id, ts, window=30):
    try:
        t = datetime.fromisoformat(ts.replace("Z","+00:00"))
    except Exception:
        t = _now()
    bef = (t-timedelta(minutes=window)).strftime("%Y-%m-%dT%H:%M:%SZ")
    aft = (t+timedelta(minutes=window)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ts0 = t.strftime("%Y-%m-%dT%H:%M:%SZ")

    raw = ix_search({"bool":{"must":[{"term":{"agent.id":agent_id}},
                                      {"range":{"timestamp":{"gte":bef,"lte":aft}}}]}},
                    size=60, sort=[{"timestamp":{"order":"asc"}}])
    events = []
    for h in raw["hits"]:
        et  = h.get("timestamp","")[:19]
        win = h.get("data",{}).get("win",{}).get("eventdata",{})
        events.append({
            "pos":    "BEFORE" if et<ts0[:19] else ("AFTER" if et>ts0[:19] else "TRIGGER"),
            "ts":     et, "level":  h.get("rule",{}).get("level",0),
            "rule":   h.get("rule",{}).get("description",""),
            "tactic": h.get("rule",{}).get("mitre",{}).get("tactic",[]),
            "src_ip": h.get("data",{}).get("srcip",""),
            "log":    h.get("full_log","")[:150],
            "cmd":    win.get("commandLine","")[:120],
            "image":  win.get("image","").split("\\")[-1],
            "parent": win.get("parentImage","").split("\\")[-1],
            "target": win.get("targetFileName","")[-80:],
            "regkey": win.get("targetObject","")[-80:],
            "user":   win.get("user",""),
        })

    bev = [e for e in events if e["pos"]=="BEFORE"]
    aev = [e for e in events if e["pos"]=="AFTER"]
    tactics  = list({t for e in events for t in e["tactic"]})
    src_ips  = list({e["src_ip"] for e in events if e["src_ip"]})
    fails    = [e for e in bev if any(w in e["rule"].lower() for w in ["fail","invalid","denied"])]
    ok       = [e for e in aev if any(w in e["rule"].lower() for w in ["accept","success","opened"])]
    fim_b    = [e for e in bev if any(w in e["rule"].lower() for w in ["integrity","file","syscheck"])]
    proc_a   = [e for e in aev if any(w in e["rule"].lower() for w in ["process","command"])]

    patterns = []
    if len(fails)>=5:
        ext = [i for i in src_ips if not i.startswith(("10.","192.168.","172."))]
        patterns.append(f"{len(fails)} auth failures "+("EXTERNAL IP" if ext else "internal IP"))
    if fails and ok:        patterns.append("Auth failures followed by success")
    if fim_b and proc_a:    patterns.append("File change before trigger + process after")
    if len(set(tactics))>=3:patterns.append(f"Multiple MITRE tactics: {tactics}")

    return {"total":len(events),"before":bev[-8:],"after":aev[:8],
            "patterns":patterns,"tactics":tactics,"src_ips":src_ips,
            "all_events":events}

# -- Behavior detection --------------------------------------------------------
BEHAVIORS = {
    "wmi_execution":     (["wmiprvse","wbem"],            ["wmiprvse.exe"]),
    "psexec":            (["psexec","psexesvc"],           ["psexesvc.exe"]),
    "lateral_smb":       (["admin$","c$ share","ipc$"],   []),
    "credential_dump":   (["lsass","secretsdump","hashdump","ntds","sam database",
                           "credential dump"],             ["lsass.exe"]),
    "pass_the_hash":     (["pass-the-hash","ntlm","pth"], []),
    "powershell":        (["powershell","encodedcommand","invoke-expression"],
                                                           ["powershell.exe","pwsh.exe"]),
    "script_drop":       (["scripting file","vbs","bat file","temp","appdata"],
                                                           ["wscript.exe","cscript.exe"]),
    "process_injection": (["process inject","hollowing","reflective"], []),
    "persistence":       (["service creat","scheduled task","registry run","autorun"],
                                                           ["schtasks.exe"]),
    "fim_change":        (["integrity checksum","file deleted","file added","syscheck"], []),
    "port_change":       (["port opened","port closed","netstat"],                       []),
    "defense_evasion":   (["log clear","vssadmin","bcdedit","wevtutil","shadow copy"],  []),
    "exploit":           (["cve-","exploit","printnightmare","spoolsv","eternalblue"],   []),
}

def detect_behaviors(events):
    found = {}
    texts = [(e, _event_text(e)) for e in events]
    for name,(rkws,pkws) in BEHAVIORS.items():
        hits = [e for e,t in texts if any(k in t for k in rkws+[p.lower() for p in pkws])]
        if hits:
            conf = "high" if pkws and any(any(p.lower() in _event_text(e)
                                              for p in pkws) for e in hits) else "medium"
            found[name] = {"confidence":conf, "count":len(hits), "events":hits[:3]}
    return found

def fmt_behaviors(beh):
    if not beh: return "  none detected"
    return NL.join(f"  [{b['confidence'].upper():6}] {name.replace('_',' ')} ({b['count']} events)"
                   for name,b in sorted(beh.items(), key=lambda x:-x[1]["count"]))

# -- Chain-driven evidence selection ------------------------------------------
SUSP_PORTS = {4444:"Metasploit",4445:"reverse shell",9001:"C2",
              6666:"backdoor",1337:"backdoor",8140:"Puppet Master"}

def _fmt_ports(items):
    return NL.join(
        f"  {p.get('local',{}).get('port'):6}  {p.get('protocol',''):5}  "
        f"{p.get('state',''):12}  {p.get('process','?')}"
        + (" [!] "+SUSP_PORTS[p.get("local",{}).get("port")]
           if p.get("local",{}).get("port") in SUSP_PORTS else "")
        for p in items) or "  none"

def _fmt_sysmon(hits):
    lines = []
    for h in hits:
        win  = h.get("data",{}).get("win",{}).get("eventdata",{})
        line = f"  {h.get('timestamp','')[:19]}  {h.get('rule',{}).get('description','')[:70]}"
        for k,label in [("commandLine","cmd"),("image","process"),
                         ("parentImage","parent"),("targetFileName","file"),
                         ("targetObject","regkey"),("user","user")]:
            val = win.get(k,"")
            if val:
                val = val.split("\\")[-1] if k in ("image","parentImage") else val[-80:]
                line += f"\n    {label:7}: {val}"
        if not any(win.get(k) for k in ("commandLine","image","targetFileName","targetObject")):
            if h.get("full_log"): line += f"\n    log    : {h['full_log'][:150]}"
        lines.append(line)
    return NL.join(lines) or "  none"

def select_enrichment(behaviors, aid, since):
    ev = {}

    # Always: ports
    try:
        ports = wget(f"/syscollector/{aid}/ports")
        ev["CURRENT_OPEN_PORTS"] = _fmt_ports(ports.get("affected_items",[]))
    except Exception as e:
        ev["CURRENT_OPEN_PORTS"] = f"  unavailable: {e}"

    # Credential dump or lateral movement -> auth timeline + processes
    if any(b in behaviors for b in ["credential_dump","pass_the_hash",
                                     "lateral_smb","wmi_execution","psexec"]):
        try:
            auth = ix_search({"bool":{"must":[
                {"term":{"agent.id":aid}},{"range":{"timestamp":{"gte":since}}},
                {"bool":{"should":[{"match":{"rule.groups":g}} for g in
                    ["authentication","sshd","sudo","pam",
                     "windows_security","win_authentication_success"]]}}]}},
                size=30, sort=[{"timestamp":{"order":"asc"}}])
            lines = []
            for h in auth["hits"]:
                evd  = h.get("data",{}).get("win",{}).get("eventdata",{})
                line = (f"  {h.get('timestamp','')[:19]}  "
                        f"[{h.get('rule',{}).get('level',0)}] "
                        f"{h.get('rule',{}).get('description','')[:55]}")
                if h.get("data",{}).get("srcip"): line += f"  src={h['data']['srcip']}"
                if evd.get("logonType"):           line += f"  logon={evd['logonType']}"
                if evd.get("authenticationPackageName"):
                    line += f"  auth={evd['authenticationPackageName']}"
                lines.append(line)
            ev["AUTH_TIMELINE"] = NL.join(lines) or "  none"
        except Exception as e:
            ev["AUTH_TIMELINE"] = f"  unavailable: {e}"

        try:
            procs = wget(f"/syscollector/{aid}/processes",{"limit":100})
            items = procs.get("affected_items",[])
            tools = [p for p in items if any(k in (p.get("name","")+p.get("cmd","")).lower()
                     for k in ["lsass","procdump","mimikatz","ntdsutil","pwdump","wce"])]
            ev["RUNNING_PROCESSES"] = NL.join(
                f"  {p.get('name','?'):25}  pid={str(p.get('pid','?')):6}  "
                f"user={p.get('euser',p.get('uname','?'))}"
                for p in items[:30]) or "  none"
            if tools:
                ev["CREDENTIAL_TOOLS_RUNNING"] = NL.join(
                    f"  [!] {p.get('name','?')}  pid={p.get('pid','?')}  "
                    f"cmd={p.get('cmd','')[:60]}" for p in tools)
        except Exception as e:
            ev["RUNNING_PROCESSES"] = f"  unavailable: {e}"

    # FIM change / script drop / persistence -> syscheck
    if any(b in behaviors for b in ["fim_change","script_drop","persistence","exploit"]):
        try:
            fim  = wget(f"/syscheck/{aid}",{"limit":50})
            items= fim.get("affected_items",[])
            SUSP = ["/tmp","/dev/shm","appdata","temp","system32","\\run","startup"]
            pri  = [i for i in items if any(s in i.get("file","").lower() for s in SUSP)]
            shown= (pri+(i for i in items if i not in pri))
            ev["FIM_CHANGES"] = NL.join(
                f"  {i.get('type','?'):10}  {i.get('file','?')}"
                f"  (size:{i.get('size','?')} mtime:{str(i.get('mtime','?'))[:10]}"
                f"  owner:{i.get('uname','?')})"
                for i in list(shown)[:15]) or "  none"
            if pri:
                ev["FIM_SUSPICIOUS"] = NL.join(
                    f"  [!] {i.get('type','?'):10}  {i.get('file','?')}" for i in pri[:8])
        except Exception:
            fb = ix_search({"bool":{"must":[
                {"term":{"agent.id":aid}},{"range":{"timestamp":{"gte":since}}},
                {"bool":{"should":[{"match":{"rule.groups":"syscheck"}},
                                    {"match":{"rule.groups":"fim"}}]}}]}},
                size=15, sort=[{"timestamp":{"order":"desc"}}])
            ev["FIM_INDEX_ALERTS"] = NL.join(
                f"  {h.get('timestamp','')[:19]}  "
                f"{h.get('rule',{}).get('description','')[:55]}  "
                f"file={h.get('syscheck',{}).get('path','?')}"
                for h in fb["hits"][:10]) or "  none"

    # PowerShell -> targeted process search
    if "powershell" in behaviors and "RUNNING_PROCESSES" not in ev:
        try:
            procs = wget(f"/syscollector/{aid}/processes",{"limit":50})
            ps    = [p for p in procs.get("affected_items",[])
                     if "powershell" in p.get("name","").lower()]
            ev["POWERSHELL_PROCESSES"] = NL.join(
                f"  {p.get('name','?')}  pid={p.get('pid','?')}  "
                f"user={p.get('euser','?')}  cmd={p.get('cmd','')[:80]}"
                for p in ps) or "  none active"
        except Exception as e:
            ev["POWERSHELL_PROCESSES"] = f"  unavailable: {e}"

    return ev

# -- Windows helpers -----------------------------------------------------------
def _is_windows(aid):
    try:
        d = wget(f"/agents/{aid}")
        if d.get("_404") or d.get("_400"): return None
        items = d.get("affected_items",[d])
        return "windows" in items[0].get("os",{}).get("name","").lower() if items else None
    except Exception:
        return None

def _sysmon_q(aid, since, groups=None, size=40):
    must = [{"term":{"agent.id":aid}},{"range":{"timestamp":{"gte":since}}}]
    if groups:
        must.append({"bool":{"should":[{"match":{"rule.groups":g}} for g in groups]}})
    return ix_search({"bool":{"must":must}}, size=size,
                     sort=[{"timestamp":{"order":"asc"}}])

# -- Evidence collection (chain-driven) ----------------------------------------
def collect(alert, since, chain=None):
    aid    = alert["agent_id"] or "000"
    is_win = _is_windows(aid)
    all_ev = (chain.get("all_events",[]) if chain else [])
    beh    = detect_behaviors(all_ev)

    # Stale/unknown agent -- indexer only
    if is_win is None:
        sysmon = _sysmon_q(aid, since,
            groups=["sysmon","windows","impacket",
                    "sysmon_eid10_detections","sysmon_eid11_detections"], size=30)
        recent = ix_search({"bool":{"must":[{"term":{"agent.id":aid}},
                                             {"range":{"timestamp":{"gte":since}}}]}},
                           size=15, sort=[{"timestamp":{"order":"desc"}}])
        return {"agent_status":   "NOT IN WAZUH ENROLLMENT -- indexer only",
                "BEHAVIORS":      fmt_behaviors(beh),
                "SYSMON_EVENTS":  _fmt_sysmon(sysmon["hits"]),
                "RECENT_ALERTS":  NL.join(
                    f"  {h.get('timestamp','')[:19]}  "
                    f"[{h.get('rule',{}).get('level',0)}] "
                    f"{h.get('rule',{}).get('description','')[:65]}"
                    for h in recent["hits"][:10]) or "  none"}

    ev = {"agent_os":"Windows" if is_win else "Linux", "BEHAVIORS":fmt_behaviors(beh)}

    # Windows: always get Sysmon events
    if is_win:
        sysmon = _sysmon_q(aid, since,
            groups=["sysmon","windows","impacket","sysmon_eid7_detections",
                    "sysmon_eid10_detections","sysmon_eid11_detections"], size=30)
        ev["SYSMON_EVENTS"] = _fmt_sysmon(sysmon["hits"])
        ev["sysmon_total"]  = sysmon["total"]

    # Chain-driven enrichment (same for Windows and Linux)
    ev.update(select_enrichment(beh, aid, since))
    return ev

def _fmt_ev(ev):
    return NL.join(f"{k}:\n{v}" if k==k.upper() and isinstance(v,str)
                   else f"  {k}: {v}" for k,v in ev.items())

def _fmt_chain(evts):
    lines = []
    for e in evts:
        line = f"    {e['ts']}  [{e['level']}] {e['rule'][:60]}"
        if e.get("src_ip"):  line += f"  src={e['src_ip']}"
        if e.get("cmd"):     line += f"\n      cmd    : {e['cmd']}"
        if e.get("image"):   line += f"\n      process: {e['image']}"
        if e.get("parent"):  line += f"\n      parent : {e['parent']}"
        if e.get("target"):  line += f"\n      file   : {e['target']}"
        if e.get("regkey"):  line += f"\n      regkey : {e['regkey']}"
        if e.get("user"):    line += f"\n      user   : {e['user']}"
        if not any(e.get(k) for k in ("cmd","image","target","regkey")) and e.get("log"):
            line += f"\n      log    : {e['log']}"
        lines.append(line)
    return NL.join(lines) or "    (none)"

# -- System prompt -------------------------------------------------------------
SYSTEM_PROMPT = """You are a senior SOC analyst. You receive:
- BEHAVIORS: patterns detected by the correlation engine (high/medium confidence)
- SYSMON_EVENTS / FIM_CHANGES / AUTH_TIMELINE: forensic evidence from Wazuh APIs
- ATTACK CHAIN: all events +-30min around the trigger (any severity)

========================================
STEP 1 -- UNDERSTAND THE EVIDENCE
========================================
Read BEHAVIORS first -- the correlation engine already identified the attack patterns.
Then read SYSMON_EVENTS and the chain for specific forensic detail.
Parent-child process relationships and command-line arguments are the most reliable evidence.

========================================
STEP 2 -- IDENTIFY MITRE ATT&CK
========================================
Derive techniques from the ACTUAL evidence -- process names, commands, registry keys,
file paths -- NOT from alert titles or rule descriptions alone.

Use your knowledge of MITRE ATT&CK to map what you observe:
- What process spawned what? -> Execution technique
- What command was run? -> Execution sub-technique
- What was accessed? (ADMIN$, LSASS, registry) -> Lateral Movement or Credential Access
- What was created? (service, scheduled task, registry key) -> Persistence technique
- What was erased or hidden? -> Defense Evasion technique

If you observe a behavior not covered by a known technique, describe it accurately
and note it is unclassified. Never fabricate technique IDs.

========================================
STEP 3 -- WRITE THE REPORT
========================================

-------------------------------------
ALERT  : <rule> | Level <N> | <agent>
TIME   : <timestamp>
STATUS : Agent <active / DISCONNECTED>
-------------------------------------
WHAT HAPPENED
  3-4 sentences. Start from BEHAVIORS. Name exact processes and commands.

KILL CHAIN
  Delivery  : <initial access vector>
  Execution : <exact command or process>
  Impact    : <lateral movement / credential access / persistence / evasion>

KEY EVIDENCE
  <3-5 lines: timestamp | process or source | action | significance>

ASSESSMENT  : Confirmed suspicious / Possibly suspicious / Likely benign
  <One paragraph. Name the attack technique or tool. Explain attacker objective.>
  A disconnected agent does NOT reduce confidence when Sysmon/chain evidence is strong.

MITRE
  Primary  : T#### -- Technique Name (Tactic)
  Secondary: T#### -- Technique Name (Tactic)  [only if directly evidenced]
  Kill chain stage: <Initial Access -> Execution -> ...>

RISK  : CRITICAL / HIGH / MEDIUM / LOW
  CRITICAL = confirmed RCE, credential dump, lateral movement, or cleanup actions
  HIGH     = strong attack indicators, incomplete confirmation
  MEDIUM   = suspicious pattern, possible false positive
  LOW      = almost certainly benign
  Reason: <one sentence -- specific evidence>

NEXT STEPS
  Immediate:
  - <containment or isolation action>
  - <evidence to preserve>
  Investigation:
  - <exact log / registry key / directory to examine>
  - <specific question to answer from the evidence>
-------------------------------------
Under 600 words. No markdown. No code blocks. Fill every field."""

# -- LLM call -----------------------------------------------------------------
def call_llm(alert, evidence, chain):
    chain_str = ""
    if chain and chain.get("total",0) > 0:
        pats = "; ".join(chain["patterns"]) if chain["patterns"] else "none"
        chain_str = (
            f"\nATTACK CHAIN ({chain['total']} events +-30min):\n"
            f"  Patterns : {pats}\n"
            f"  Src IPs  : {', '.join(chain['src_ips']) or 'none'}\n"
            f"  MITRE    : {', '.join(chain['tactics']) or 'none'}\n"
            f"  BEFORE:\n{_fmt_chain(chain['before'][-4:])}\n"
            f"  AFTER:\n{_fmt_chain(chain['after'][:4])}\n"
        )
    prompt = (
        f"Alert  : [{alert['level']}] {alert['rule']}\n"
        f"Agent  : {', '.join(alert['agents'])} (ID: {alert['agent_id']})\n"
        f"Time   : {alert['ts']}\n"
        f"Src IP : {alert['src_ip'] or 'none'} | User: {alert['src_user'] or 'none'}\n"
        f"Log    : {alert['log']}\n"
        f"MITRE  : {alert['tactics']}\n\n"
        f"EVIDENCE:\n{_fmt_ev(evidence)}\n{chain_str}\nWrite the report."
    )
    client = ollama.Client(host=C["OL_HOST"])
    t0, result, first = time.perf_counter(), "", True

    # Show a live elapsed timer while the model is reasoning/generating.
    # qwen3 and similar models have a thinking phase that produces no visible
    # output — without this the terminal looks frozen.
    import threading

    done  = threading.Event()
    timer_line = [0]   # mutable so the thread can update it

    def _ticker():
        chars = ["|", "/", "-", "\\"]
        i = 0
        while not done.is_set():
            elapsed = int(time.perf_counter() - t0)
            sys.stdout.write(f"\r  Analysing... {chars[i % 4]} {elapsed}s elapsed")
            sys.stdout.flush()
            i += 1
            time.sleep(0.5)

    ticker = threading.Thread(target=_ticker, daemon=True)
    ticker.start()

    try:
        for chunk in client.chat(model=C["MODEL"], messages=[
            {"role":"system","content":SYSTEM_PROMPT},
            {"role":"user",  "content":prompt}
        ], stream=True):
            if STOP_FLAG.is_set():
                done.set()
                break
            text = chunk.message.content
            if text:
                if first:
                    done.set()       # signal ticker to stop
                    ticker.join()    # wait for it to fully finish writing
                    # Clear the ticker line completely before printing report
                    sys.stdout.write("\r" + " " * 60 + "\r")
                    elapsed = int(time.perf_counter() - t0)
                    sys.stdout.write(f"  Thinking done ({elapsed}s). Generating report...\n\n")
                    sys.stdout.flush()
                    first = False
                print(text, end="", flush=True)
                result += text
        print()
    except Exception as e:
        done.set()
        ticker.join()
        err = str(e)
        print(f"\n  ERR {err}")
        if "not found" in err.lower(): print(f"     -> Run: ollama pull {C['MODEL']}")
        elif "connection" in err.lower(): print("     -> Run: ollama serve")
        result = f"[unavailable -- {err}]"
    finally:
        done.set()

    elapsed = int(time.perf_counter()-t0)
    log.debug("Ollama -> %ds | %d chars generated", elapsed, len(result))
    if not result.strip():
        log.warning("Ollama returned EMPTY result after %ds", elapsed)
    else:
        log.info("Ollama report: first 200 chars: %s", result[:200])
    return result

# -- Main ---------------------------------------------------------------------
_enrolled = {}

# Stop flag — set by the UI to interrupt a running investigation
import threading as _threading
STOP_FLAG = _threading.Event()

def run(severity=MIN_SEV, hours=HOURS, agent_id=None):
    global _enrolled
    since = _since(hours)
    print(f"\n{'='*56}\n  Wazuh Correlation Agent | Ollama ({C['MODEL']})")
    print(f"  Severity : level >= {severity} | Period: last {hours}h")
    print(f"  Target   : {f'agent {agent_id}' if agent_id else 'all agents'}\n{'='*56}\n")

    try:
        fleet = wget("/agents",{"limit":500,"select":"id,name,status"})
        _enrolled = {a["id"]:a.get("name","?") for a in fleet.get("affected_items",[])}
    except Exception as e:
        log.debug("Agent list unavailable: %s", e)

    print("  Fetching alerts...", end="", flush=True)
    try:
        total, dist, alerts = fetch_alerts(since, severity, agent_id)
    except RuntimeError as e:
        print(f"\n\n  ERR FATAL: {e}\n"); return
    except Exception as e:
        print(f"\n\n  ERR {type(e).__name__}: {e}\n"); return

    print(f" {total} total")
    for k,v in dist.items(): print(f"    {k}: {v}")
    if not alerts: print("\n  No alerts found.\n"); return

    print(f"\n  Alert groups (deduplicated):")
    for i,a in enumerate(alerts[:10],1):
        cov = (f"  covers: {', '.join(a['covered'][:3])}"
               if len(a.get("covered",[]))>1 else "")
        print(f"     {i}. [{a['level']}] {a['group'][:45]}  (x{a['count']}){cov}")

    # One slot per type, max 5
    seen, top = set(), []
    TYPES = {"fim":["syscheck","fim"],"auth":["authentication","windows_security"],
             "port":["network_changes","netstat"],"process":["sysmon","windows","impacket"]}
    def _type(g):
        for t,kws in TYPES.items():
            if any(k in g for k in kws): return t
        return "generic"
    for a in alerts:
        t = _type(a["group"])
        if t not in seen: seen.add(t); top.append(a)
        if len(top)>=5: break
    if not top: top = alerts[:3]

    # Chains -- one per agent
    chains = {}
    for aid in {a["agent_id"] or agent_id or "000" for a in top}:
        ts = next((a["ts"] for a in top if (a["agent_id"] or "000")==aid), None)
        if not ts: continue
        print(f"\n  Building attack chain for agent {aid}...", end="", flush=True)
        try:
            chains[aid] = get_chain(aid, ts)
            c = chains[aid]
            print(f" OK  {c['total']} events")
            for pat in c["patterns"]: print(f"    ** {pat}")
            if _enrolled and aid not in _enrolled:
                print(f"    [!]  Agent {aid} not enrolled. "
                      f"Enrolled: {', '.join(f'{i}={n}' for i,n in _enrolled.items())}")
        except Exception as e:
            print(f" ERR {e}"); chains[aid] = None

    print(f"\n{'='*56}\n  ANALYSIS ({len(top)} alert{'s' if len(top)>1 else ''})\n{'='*56}")
    for i,alert in enumerate(top,1):
        aid   = alert["agent_id"] or agent_id or "000"
        chain = chains.get(aid)
        print(f"\n  Collecting evidence for alert {i}/{len(top)}...", end="", flush=True)
        try:
            evidence = collect(alert, since, chain=chain)
            print(" OK")
        except RuntimeError as e:
            print(f"\n  [!]  Skipped -- {e}")
            evidence = {"agent_status":"DISCONNECTED or unreachable",
                        "note":"Evidence unavailable -- analysis from chain only."}
        except Exception as e:
            print(f"\n  ERR  {type(e).__name__}: {e}")
            evidence = {"error":str(e)}
        if STOP_FLAG.is_set():
            print("\n  [Stopped by user]")
            break
        print(); call_llm(alert, evidence, chain)

    all_ips = {ip for c in chains.values() if c for ip in c["src_ips"]}
    if all_ips:
        print(f"\n{'-'*56}\n  SOURCE IPs\n{'-'*56}")
        for ip in sorted(all_ips):
            internal = any(ip.startswith(p) for p in
                ("10.","192.168.","172.16.","172.17.","172.18.","172.19.",
                 "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.",
                 "172.26.","172.27.","172.28.","172.29.","172.30.","172.31."))
            print(f"  {ip:22s}  {'internal' if internal else '[!]  EXTERNAL'}")
    print()

def run_from_prompt(prompt: str):
    """
    Accept a natural language prompt, use Ollama to extract investigation
    parameters, then run the full correlation pipeline.

    This is the entry point for the Wazuh dashboard assistant integration.
    The prompt goes to Ollama once for parameter extraction (fast, no streaming,
    temperature=0), then the full investigation runs with those parameters.

    Examples:
      "check agent 000 severity 5 last 24 hours"
      "investigate all agents high severity events today"
      "what happened on agent 004 in the past 48 hours"
    """
    extraction_prompt = (
        f"Extract Wazuh investigation parameters from this message.\n"
        f"Message: \"{prompt}\"\n\n"
        f"Return ONLY a JSON object with these fields:\n"
        f"  agent: the agent ID (e.g. \"000\", \"004\"). Empty string if all agents.\n"
        f"  severity: minimum alert severity level (integer 3-15).\n"
        f"    Map: all/any/everything=3, low=5, medium=7, high=10, critical=12.\n"
        f"    If the user says \"severity 5\" or \"level 5\", use 5.\n"
        f"    Default: 7\n"
        f"  hours: time window in hours (integer).\n"
        f"    Map: today=24, this week=168, 1 hour=1.\n"
        f"    Default: 24\n\n"
        f"Return ONLY the JSON, nothing else. Example:\n"
        f'{{\"agent\": \"000\", \"severity\": 5, \"hours\": 24}}'
    )

    # Extract parameters using Ollama — single fast call, no streaming
    severity = MIN_SEV
    hours    = HOURS
    agent_id = None
    try:
        client   = ollama.Client(host=C["OL_HOST"])
        response = client.chat(
            model=C["MODEL"],
            messages=[{"role": "user", "content": extraction_prompt}],
            stream=False,
            options={"temperature": 0, "num_predict": 60}
        )
        import json as _json, re as _re
        text = response.message.content.strip()
        log.debug("Parameter extraction response: %s", text)
        m = _re.search(r'\{[^}]+\}', text, _re.DOTALL)
        if m:
            parsed   = _json.loads(m.group())
            severity = int(parsed.get("severity", MIN_SEV))
            hours    = int(parsed.get("hours",    HOURS))
            agent    = str(parsed.get("agent",    "")).strip()
            agent_id = agent if agent else None
            log.info("Extracted: severity=%d hours=%d agent=%s",
                     severity, hours, agent_id or "all")
    except Exception as e:
        log.warning("Parameter extraction failed (%s) — using defaults", e)

    # Run the full investigation with extracted parameters
    log.info("Starting investigation: severity=%d hours=%d agent=%s",
             severity, hours, agent_id or "all")
    run(severity=severity, hours=hours, agent_id=agent_id)
    log.info("Investigation complete")


def main():
    p = argparse.ArgumentParser(description=f"Wazuh Correlation Agent [Ollama]")
    p.add_argument("--severity", type=int, default=MIN_SEV)
    p.add_argument("--hours",    type=int, default=HOURS)
    p.add_argument("--agent",    type=str, default=None)
    p.add_argument("--debug",    action="store_true")
    args = p.parse_args()
    if args.debug:
        global log; log = _setup_logger(debug=True)
        log.debug("Debug | model=%s | severity>=%d | hours=%d",
                  C["MODEL"], args.severity, args.hours)
    run(args.severity, args.hours, args.agent)

if __name__ == "__main__":
    main()