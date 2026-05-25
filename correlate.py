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

    print(f"  [indexer] Fetching event timeline for agent {agent_id} "
          f"({bef[11:16]} to {aft[11:16]})...")
    raw = ix_search({"bool":{"must":[{"term":{"agent.id":agent_id}},
                                      {"range":{"timestamp":{"gte":bef,"lte":aft}}}]}},
                    size=60, sort=[{"timestamp":{"order":"asc"}}])
    print(f"  [indexer] Found {raw['total']} events in timeline")
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
        print(f"  [server api] GET /syscollector/{aid}/ports — open ports and listening services")
        ports = wget(f"/syscollector/{aid}/ports")
        ev["CURRENT_OPEN_PORTS"] = _fmt_ports(ports.get("affected_items",[]))
    except Exception as e:
        ev["CURRENT_OPEN_PORTS"] = f"  unavailable: {e}"

    # Credential dump or lateral movement -> auth timeline + processes
    if any(b in behaviors for b in ["credential_dump","pass_the_hash",
                                     "lateral_smb","wmi_execution","psexec"]):
        try:
            print(f"  [indexer] Querying authentication timeline for agent {aid}...")
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
            print(f"  [server api] GET /syscollector/{aid}/processes — checking for credential dump tools")
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
            print(f"  [server api] GET /syscheck/{aid} — file integrity changes")
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
            print(f"  [server api] GET /syscollector/{aid}/processes — looking for active PowerShell")
            procs = wget(f"/syscollector/{aid}/processes",{"limit":50})
            ps    = [p for p in procs.get("affected_items",[])
                     if "powershell" in p.get("name","").lower()]
            ev["POWERSHELL_PROCESSES"] = NL.join(
                f"  {p.get('name','?')}  pid={p.get('pid','?')}  "
                f"user={p.get('euser','?')}  cmd={p.get('cmd','')[:80]}"
                for p in ps) or "  none active"
        except Exception as e:
            ev["POWERSHELL_PROCESSES"] = f"  unavailable: {e}"

    # Installed packages — relevant for exploit, persistence, defense_evasion
    # Helps the model identify vulnerable or suspicious software
    if any(b in behaviors for b in ["exploit", "persistence", "defense_evasion",
                                     "script_drop", "process_injection"]):
        try:
            print(f"  [server api] GET /syscollector/{aid}/packages — installed software inventory")
            pkgs = wget(f"/syscollector/{aid}/packages", {"limit": 100})
            items = pkgs.get("affected_items", [])
            if items:
                # Flag packages that are commonly abused or indicate risk
                SUSPECT = ["python", "perl", "ruby", "php", "nmap", "netcat", "nc",
                           "mimikatz", "metasploit", "sqlmap", "hydra", "john",
                           "wireshark", "tcpdump", "putty", "winscp", "psexec",
                           "sysinternals", "powersploit", "invoke-", "cobalt"]
                flagged = []
                all_pkgs = []
                for p in items:
                    name    = p.get("name", "")
                    version = p.get("version", "")
                    vendor  = p.get("vendor", "")
                    all_pkgs.append(f"{name} {version}".strip())
                    if any(s in name.lower() for s in SUSPECT):
                        flagged.append(f"  [FLAGGED] {name} {version} ({vendor})")

                lines = []
                if flagged:
                    lines.append("Flagged packages (potentially suspicious):")
                    lines.extend(flagged)
                # Show total count and a sample of recent/notable packages
                lines.append(f"Total installed: {len(items)} packages")
                # Show last 10 (often most recently installed)
                lines.append("Recently indexed (sample):")
                for p in items[-10:]:
                    lines.append(f"  {p.get('name','')} {p.get('version','')} — {p.get('vendor','unknown vendor')}")
                ev["INSTALLED_PACKAGES"] = "\n".join(lines)
            else:
                ev["INSTALLED_PACKAGES"] = "  no package data available (agent may be offline)"
        except Exception as e:
            ev["INSTALLED_PACKAGES"] = f"  unavailable: {e}"

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
                "behaviors_raw":  beh,
                "BEHAVIORS":      fmt_behaviors(beh),
                "SYSMON_EVENTS":  _fmt_sysmon(sysmon["hits"]),
                "RECENT_ALERTS":  NL.join(
                    f"  {h.get('timestamp','')[:19]}  "
                    f"[{h.get('rule',{}).get('level',0)}] "
                    f"{h.get('rule',{}).get('description','')[:65]}"
                    for h in recent["hits"][:10]) or "  none"}

    ev = {"agent_os":"Windows" if is_win else "Linux", "BEHAVIORS":fmt_behaviors(beh),
           "behaviors_raw": beh}

    # Windows: always get Sysmon events
    if is_win:
        print(f"  [indexer] Querying Sysmon/Windows events for agent {aid}...")
        sysmon = _sysmon_q(aid, since,
            groups=["sysmon","windows","impacket","sysmon_eid7_detections",
                    "sysmon_eid10_detections","sysmon_eid11_detections"], size=30)
        print(f"  [indexer] Found {sysmon['total']} Sysmon events")
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
SYSTEM_PROMPT = """You are a SOC analyst. Write a short security report using only the evidence provided.

Rules:
- Plain text only. No markdown. No bold. No tables.
- Use dashes for bullets.
- Name exact processes, file paths, timestamps from the evidence.
- For MITRE: use tactic names only (Execution, Persistence, etc). Do not write T#### IDs.
- Stop writing after NEXT STEPS.

Format:

WHAT HAPPENED
- [timestamp] [process] [exact action]
- [timestamp] [process] [exact action]
- [timestamp] [process] [exact action]

ATTACK CHAIN
- Delivery: [how attacker got in]
- Execution: [exact command or process used]
- Impact: [persistence / credential access / lateral movement / evasion]

MITRE ATT&CK
- Primary tactic: [tactic name] - [technique description]
- Secondary tactic: [tactic name] - [technique description]

NEXT STEPS
Immediate:
- [specific containment action]
- [specific evidence to preserve]
Investigate:
- [exact file, registry key, or log]
- [specific question from the evidence]
"""


# -- LLM call -----------------------------------------------------------------
# MITRE ATT&CK tactics — stable, only 14 of them, never change
# Used to validate that the model uses tactic names not invented technique IDs.
MITRE_TACTICS = {
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
    "Reconnaissance", "Resource Development"
}

import re as _re

def _validate_report(report, behaviors):
    """
    Lightweight post-generation check. No model call — pure Python.
    Only checks structural completeness and risk calibration.
    MITRE validation removed — tactic names are enforced via system prompt,
    not a curated ID list that requires constant maintenance.
    """
    problems = []
    report_upper = report.upper()

    # Required sections present
    for section in ["WHAT HAPPENED", "RISK", "NEXT STEPS"]:
        if section not in report_upper:
            problems.append(f"Missing section: {section}")

    # CRITICAL risk without HIGH-confidence Python-detected behavior
    if "CRITICAL" in report_upper:
        has_high = any(
            b.get("confidence") == "high"
            for b in behaviors.values()
        ) if behaviors else False
        if not has_high:
            problems.append("CRITICAL risk with no HIGH-confidence behaviors detected")

    return problems


def call_llm(alert, evidence, chain):
    """Single model call with thinking disabled for speed."""
    import threading, re as _reval

    chain_str = ""
    if chain and chain.get("total", 0) > 0:
        pats = "; ".join(chain["patterns"]) if chain["patterns"] else "none"
        chain_str = (
            f"\nATTACK CHAIN ({chain['total']} events +-30min):\n"
            f"  Patterns : {pats}\n"
            f"  Src IPs  : {', '.join(chain['src_ips']) or 'none'}\n"
            f"  BEFORE:\n{_fmt_chain(chain['before'][-3:])}\n"
            f"  AFTER:\n{_fmt_chain(chain['after'][:3])}\n"
        )

    # Cap evidence at 6000 chars to stay within context window.
    # Python-assembled header is not sent to the model — only the body prompt.
    ev_str    = _fmt_ev(evidence)
    if len(ev_str) > 6000:
        ev_str = ev_str[:6000] + "\n[evidence truncated for context limit]"

    prompt = (
        f"Alert  : [{alert['level']}] {alert['rule']}\n"
        f"Agent  : {', '.join(alert['agents'])} (ID: {alert['agent_id']})\n"
        f"Time   : {alert['ts']}\n"
        f"Src IP : {alert['src_ip'] or 'none'} | User: {alert['src_user'] or 'none'}\n"
        f"Log    : {alert['log']}\n"
        f"MITRE  : {alert['tactics']}\n\n"
        f"EVIDENCE:\n{ev_str}\n{chain_str}"
    )
    log.debug("Prompt length: %d chars", len(prompt))

    client = ollama.Client(host=C["OL_HOST"])
    t0     = time.perf_counter()

    # Ticker
    done = threading.Event()
    def _ticker():
        chars = ["|", "/", "-", "\\"]
        i = 0
        while not done.is_set():
            elapsed = int(time.perf_counter() - t0)
            sys.stdout.write(f"\r  Analysing... {chars[i%4]} {elapsed}s")
            sys.stdout.flush()
            i += 1
            time.sleep(0.5)
    threading.Thread(target=_ticker, daemon=True).start()

    result = ""
    in_think = False
    try:
        for chunk in client.chat(
            model=C["MODEL"],
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt}
            ],
            stream=True,
            options={
                "temperature": 0,
                "num_ctx":     8192,
                "num_predict": 2000,   # thinking tokens + report body both fit
            }
        ):
            if STOP_FLAG.is_set():
                done.set()
                break
            text = chunk.message.content
            if not text:
                continue
            result += text
            # Track <think> block — suppress from display and result
            if "<think>" in result and not in_think:
                in_think = True
            if in_think:
                if "</think>" in result:
                    import re as _rt
                    result = _rt.sub(r"<think>.*?</think>", "", result,
                                     flags=_rt.DOTALL).strip()
                    # Also strip any leading garbage before </think>
                    result = _rt.sub(r"^.*?</think>", "", result,
                                     flags=_rt.DOTALL).strip()
                    in_think = False
                    if result and not done.is_set():
                        done.set()
                        sys.stdout.write("\r" + " " * 60 + "\r")
                        elapsed = int(time.perf_counter() - t0)
                        sys.stdout.write(f"  Generating ({elapsed}s thinking)...\n\n")
                        sys.stdout.flush()
                        print(result, end="", flush=True)
                continue  # still in think block, don't print
            # Normal output token
            if result and not done.is_set():
                done.set()
                sys.stdout.write("\r" + " " * 60 + "\r")
                elapsed = int(time.perf_counter() - t0)
                sys.stdout.write(f"  Generating ({elapsed}s thinking)...\n\n")
                sys.stdout.flush()
            print(text, end="", flush=True)
        print()
    except Exception as e:
        done.set()
        err = str(e)
        print(f"\n  ERR {err}")
        if "not found" in err.lower(): print(f"     -> Run: ollama pull {C['MODEL']}")
        elif "connection" in err.lower(): print("     -> Run: ollama serve")
        result = f"[unavailable -- {err}]"
    finally:
        done.set()

    elapsed = int(time.perf_counter() - t0)
    log.info("Ollama -> %ds | %d chars", elapsed, len(result))

    # Strip thinking tokens
    import re as _rethink
    # Final cleanup of any remaining think artifacts
    import re as _rethink
    result = _rethink.sub(r"<think>.*?</think>", "", result, flags=_rethink.DOTALL)
    result = _rethink.sub(r"^.*?</think>", "", result, flags=_rethink.DOTALL)
    result = result.strip()

    # Python builds the header — not the model
    behaviors = evidence.get("behaviors_raw", {})
    high_conf = [k for k, v in behaviors.items() if v.get("confidence") == "high"]
    med_conf  = [k for k, v in behaviors.items() if v.get("confidence") == "medium"]
    critical  = {"credential_dump","lateral_smb","wmi_execution",
                 "pass_the_hash","process_injection","exploit"}
    if any(b in critical for b in high_conf) or len(high_conf) >= 2:
        risk = "CRITICAL"
    elif high_conf or len(med_conf) >= 2:
        risk = "HIGH"
    elif med_conf:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    status = "Disconnected" if "NOT IN WAZUH" in evidence.get("agent_status","")              else "Active"
    os_    = evidence.get("agent_os", "Unknown")

    beh_str = ""
    if behaviors:
        beh_str = "\nDETECTED BEHAVIORS\n" + "\n".join(
            f"- {k.replace('_',' ').title()} [{v['confidence'].upper()}]"
            for k, v in behaviors.items()
        ) + "\n"

    report = (
        f"AGENT   : {', '.join(alert['agents'])} (ID: {alert['agent_id']}) | {os_}\n"
        f"TIME    : {alert['ts']}\n"
        f"STATUS  : {status}\n"
        f"RISK    : {risk}\n"
        f"{beh_str}\n"
        f"{result}\n"
    )

    # No MITRE ID validation — system prompt instructs tactic names only

    print("\n" + report)
    log.info("Report done: %d chars, risk=%s", len(report), risk)
    return report

# -- Main ---------------------------------------------------------------------
_enrolled = {}

# Stop flag — set by the UI to interrupt a running investigation
import threading as _threading
STOP_FLAG = _threading.Event()

def run(severity=MIN_SEV, hours=HOURS, agent_id=None):
    global _enrolled
    since = _since(hours)
    print(f"severity>={severity} | last {hours}h | "
          f"{'agent '+agent_id if agent_id else 'all agents'}\n")

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

    if not alerts: print("  No alerts found.\n"); return
    log.debug("Alerts: %d total, groups: %s", total, [a['group'] for a in alerts[:5]])

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
        log.debug("Building attack chain for agent %s", aid)
        try:
            chains[aid] = get_chain(aid, ts)
            c = chains[aid]
            log.debug("Chain: %d events, patterns: %s", c['total'], c['patterns'])
        except Exception as e:
            print(f" ERR {e}"); chains[aid] = None

    log.debug("Analysing %d alert group(s)", len(top))
    for i,alert in enumerate(top,1):
        aid   = alert["agent_id"] or agent_id or "000"
        chain = chains.get(aid)
        log.debug("Collecting evidence for alert %d/%d", i, len(top))
        try:
            evidence = collect(alert, since, chain=chain)
            # Print the trigger alert as context before the report
            print(f"TRIGGER ALERT")
            print(f"- Rule    : [{alert['level']}] {alert['rule']}")
            print(f"- Agent   : {', '.join(alert['agents'])} (ID: {alert['agent_id']})")
            print(f"- Time    : {alert['ts']}")
            if alert['src_ip']: print(f"- Src IP  : {alert['src_ip']}")
            if alert['tactics']: print(f"- Tactics : {', '.join(alert['tactics'])}")
            print()
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