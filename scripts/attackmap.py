"""Attack map: honeypot / sensor observations, normalized to a T-Pot-like event shape.

Default source: SANS Internet Storm Center / DShield (https://isc.sans.edu/api/), keyless.
DShield aggregates firewall and honeypot logs from volunteer sensors worldwide. It reports
where scanning/attack traffic comes FROM (source IP, its network's country) and which ports it
hits. It does not publish where its sensors are, so rows carry no destination location.

Optional source: your own T-Pot honeypot. Set TPOT_ES_URL (e.g. http://127.0.0.1:64298) and,
if needed, TPOT_ES_USER / TPOT_ES_PASS. Skipped when unset. Rows then carry real destination
countries (the honeypot's location).

Output
  data/attackmap.json       latest snapshot + daily history
  data/dash/attackmap.json  flat rows for the dashboard, one `kind` per panel:
      country  attack sources aggregated by the source network's country
      ip       the busiest source IPs (with AS name and country)
      port     most-targeted destination ports
      day      daily totals reported by DShield
"""
import base64
import ipaddress
import json
import os
import time
from collections import defaultdict
from datetime import timedelta

from common import (COUNTRY_NAMES, days_ago, europe_scope, http_get, iso2, load, now_iso, now_utc,
                    record_health, save)

ISC = "https://isc.sans.edu/api"
# DShield asks API users to identify themselves; common.UA already names the repo.
LOOKUPS = 40          # per-IP country lookups per run (polite: ~1 request/second)
TOP_IPS = 100
TOP_PORTS = 20

# Well-known service names for common destination ports (own list, public knowledge).
SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP-alt", 110: "POP3",
    111: "RPC", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS", 139: "NetBIOS/SMB", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 502: "Modbus", 587: "SMTP", 623: "IPMI",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle DB", 1723: "PPTP",
    1883: "MQTT", 1900: "SSDP", 2222: "SSH-alt", 2323: "Telnet-alt", 2375: "Docker API", 2376: "Docker API",
    3128: "HTTP proxy", 3306: "MySQL", 3389: "RDP", 4444: "Metasploit", 5060: "SIP", 5432: "PostgreSQL",
    5555: "Android ADB", 5900: "VNC", 5901: "VNC", 6379: "Redis", 6443: "Kubernetes API", 7547: "TR-069",
    8000: "HTTP-alt", 8080: "HTTP-alt", 8081: "HTTP-alt", 8088: "HTTP-alt", 8443: "HTTPS-alt",
    8888: "HTTP-alt", 9000: "HTTP-alt", 9200: "Elasticsearch", 10000: "Webmin", 11211: "Memcached",
    27017: "MongoDB", 37215: "Huawei UPnP", 49152: "UPnP", 52869: "UPnP",
}

TARGET_DSHIELD = "DShield sensors (worldwide)"


def service(port):
    try:
        return SERVICES.get(int(port), "Other")
    except (TypeError, ValueError):
        return "Other"


def _num(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def _ip(v):
    """DShield zero-pads octets (045.148.010.240)."""
    try:
        return str(ipaddress.ip_address(".".join(str(int(p)) for p in str(v).strip().split("."))))
    except Exception:
        return ""


def _rows(obj):
    """DShield answers as a list, or as a dict keyed "0", "1", ... plus metadata keys."""
    if isinstance(obj, list):
        return [r for r in obj if isinstance(r, dict)]
    if isinstance(obj, dict):
        for k in ("data", "items", "results"):
            if isinstance(obj.get(k), list):
                return obj[k]
        return [v for k, v in sorted(obj.items(), key=lambda kv: (len(kv[0]), kv[0])) if k.isdigit() and isinstance(v, dict)]
    return []


def _get(path, date=None):
    url = f"{ISC}/{path}" + (f"/{date}" if date else "") + "?json"
    return http_get(url, timeout=60, retries=1)


def fetch_dshield():
    day = days_ago(1)  # last complete UTC day
    detail = {"day": day}

    # 1. busiest source IPs
    src = _rows(_get(f"sources/attacks/{TOP_IPS}", day))
    if not src:
        src = _rows(_get(f"sources/attacks/{TOP_IPS}"))
        detail["sources_fallback"] = "today (yesterday empty)"
    if not src:
        raise RuntimeError("sources endpoint returned no rows")
    detail["sources_keys"] = sorted(src[0].keys())[:12]
    ips = []
    for r in src:
        ip = _ip(r.get("ip") or r.get("source") or r.get("ipaddr"))
        if not ip:
            continue
        ips.append({"ip": ip, "reports": _num(r.get("count", r.get("reports"))),
                    "targets": _num(r.get("attacks", r.get("targets"))),
                    "firstseen": str(r.get("firstseen") or "")[:10], "lastseen": str(r.get("lastseen") or "")[:10]})
    ips.sort(key=lambda r: r["reports"], reverse=True)

    # 2. country + network for the busiest IPs (cached between runs; network owners rarely change)
    cache = load("attackmap_ipcache.json", {})
    fresh = 0
    for r in ips[:LOOKUPS]:
        c = cache.get(r["ip"])
        if not c or c.get("at", "") < days_ago(30):
            try:
                info = http_get(f"{ISC}/ip/{r['ip']}?json", timeout=30, retries=1)
                info = info.get("ip", info) if isinstance(info, dict) else {}
                c = {"cc": iso2(info.get("ascountry") or info.get("country")),
                     "asname": str(info.get("asname") or "")[:80], "as": str(info.get("as") or ""), "at": now_iso()[:10]}
                cache[r["ip"]] = c
                fresh += 1
            except Exception as e:
                detail.setdefault("lookup_errors", []).append(str(e)[:120])
                c = None
            time.sleep(1.2)
        if c:
            r.update(country=c["cc"], asname=c["asname"], asn=c["as"])
    # drop cache entries not seen for 60 days
    cutoff = days_ago(60)
    cache = {k: v for k, v in cache.items() if v.get("at", "") >= cutoff}
    save("attackmap_ipcache.json", cache)
    detail["lookups_fresh"] = fresh
    if detail.get("lookup_errors"):
        detail["lookup_errors"] = detail["lookup_errors"][:5]

    # 3. most-targeted ports
    ports = []
    try:
        pr = _rows(_get(f"topports/records/{TOP_PORTS}", day))
        detail["ports_keys"] = sorted(pr[0].keys())[:12] if pr else []
        for r in pr:
            p = r.get("targetport", r.get("port"))
            if p in (None, ""):
                continue
            ports.append({"port": _num(p), "records": _num(r.get("records")), "targets": _num(r.get("targets")),
                          "sources": _num(r.get("sources"))})
    except Exception as e:
        detail["ports_error"] = str(e)[:200]

    # 4. daily totals for a two-week trend
    days = []
    try:
        dr = _rows(_get(f"dailysummary/{days_ago(14)}/{day}"))
        for r in dr:
            d = str(r.get("date") or "")[:10]
            if d:
                days.append({"date": d, "records": _num(r.get("records")), "targets": _num(r.get("targets")),
                             "sources": _num(r.get("sources"))})
    except Exception as e:
        detail["daily_error"] = str(e)[:200]

    return {"day": day, "ips": ips, "ports": ports, "days": days, "detail": detail}


def fetch_tpot():
    """Aggregate the last 24 h of events from your own T-Pot Elasticsearch (optional)."""
    base = os.environ.get("TPOT_ES_URL", "").rstrip("/")
    if not base:
        return None
    headers = {"Content-Type": "application/json"}
    if os.environ.get("TPOT_ES_USER"):
        tok = base64.b64encode(f"{os.environ['TPOT_ES_USER']}:{os.environ.get('TPOT_ES_PASS', '')}".encode()).decode()
        headers["Authorization"] = "Basic " + tok
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "src": {"terms": {"field": "geoip.country_code2", "size": 60},
                    "aggs": {"dst": {"terms": {"field": "geoip_ext.country_code2", "size": 5}}}},
            "ports": {"terms": {"field": "dest_port", "size": TOP_PORTS}},
            "ips": {"terms": {"field": "src_ip", "size": 25},
                    "aggs": {"cc": {"terms": {"field": "geoip.country_code2", "size": 1}}}},
        },
    }
    res = http_get(f"{base}/logstash-*/_search", headers=headers, method="POST",
                   body=json.dumps(body).encode(), timeout=60, retries=1)
    aggs = res.get("aggregations", {})
    return {
        "src": [(b["key"], b["doc_count"], [(d["key"], d["doc_count"]) for d in b.get("dst", {}).get("buckets", [])])
                for b in aggs.get("src", {}).get("buckets", [])],
        "ports": [(b["key"], b["doc_count"]) for b in aggs.get("ports", {}).get("buckets", [])],
        "ips": [(b["key"], b["doc_count"], (b.get("cc", {}).get("buckets") or [{}])[0].get("key", ""))
                for b in aggs.get("ips", {}).get("buckets", [])],
    }


def _country_row(src, day, cc, n, ips, targets, dst_cc="", target=TARGET_DSHIELD):
    return {
        "id": f"{src}|country|{cc or 'XX'}|{dst_cc or 'any'}", "kind": "country", "source": src, "date": day,
        "src_country": cc, "src_country_name": COUNTRY_NAMES.get(cc, cc) or "Unknown", "src_scope": europe_scope(cc),
        "dst_country": dst_cc, "dst_country_name": COUNTRY_NAMES.get(dst_cc, dst_cc), "target": target,
        "count": n, "ips": ips, "targets": targets,
    }


def build_rows(ds, tp):
    rows = []
    if ds:
        day = ds["day"]
        looked = [r for r in ds["ips"] if "country" in r]
        by = defaultdict(lambda: {"n": 0, "ips": 0, "t": 0})
        for r in looked:
            b = by[r.get("country") or ""]
            b["n"] += r["reports"]; b["ips"] += 1; b["t"] += r["targets"]
        for cc, b in by.items():
            rows.append(_country_row("dshield", day, cc, b["n"], b["ips"], b["t"]))
        for i, r in enumerate(ds["ips"][:25], 1):
            cc = r.get("country", "")
            rows.append({"id": f"dshield|ip|{r['ip']}", "kind": "ip", "source": "dshield", "date": day, "rank": i,
                         "src_ip": r["ip"], "src_country": cc, "src_country_name": COUNTRY_NAMES.get(cc, cc) or "Unknown",
                         "src_scope": europe_scope(cc), "asname": r.get("asname", ""), "count": r["reports"],
                         "targets": r["targets"], "first_seen": r["firstseen"], "last_seen": r["lastseen"],
                         "target": TARGET_DSHIELD})
        for i, p in enumerate(ds["ports"], 1):
            rows.append({"id": f"dshield|port|{p['port']}", "kind": "port", "source": "dshield", "date": day, "rank": i,
                         "dst_port": p["port"], "protocol": service(p["port"]), "count": p["records"],
                         "targets": p["targets"], "sources": p["sources"], "target": TARGET_DSHIELD})
        for d in ds["days"]:
            rows.append({"id": f"dshield|day|{d['date']}", "kind": "day", "source": "dshield", "date": d["date"],
                         "count": d["records"], "targets": d["targets"], "sources": d["sources"]})
    if tp:
        day = now_utc().strftime("%Y-%m-%d")
        for cc, n, dsts in tp["src"]:
            cc = iso2(cc)
            for dcc, dn in (dsts or [("", n)]):
                rows.append(_country_row("tpot", day, cc, dn, None, None, iso2(dcc), "Own T-Pot honeypot"))
        for i, (ip, n, cc) in enumerate(tp["ips"], 1):
            cc = iso2(cc)
            rows.append({"id": f"tpot|ip|{ip}", "kind": "ip", "source": "tpot", "date": day, "rank": i, "src_ip": ip,
                         "src_country": cc, "src_country_name": COUNTRY_NAMES.get(cc, cc) or "Unknown",
                         "src_scope": europe_scope(cc), "count": n, "target": "Own T-Pot honeypot"})
        for i, (port, n) in enumerate(tp["ports"], 1):
            rows.append({"id": f"tpot|port|{port}", "kind": "port", "source": "tpot", "date": day, "rank": i,
                         "dst_port": _num(port), "protocol": service(port), "count": n, "target": "Own T-Pot honeypot"})
    return rows


def cmd_attackmap():
    ds = tp = None
    try:
        ds = fetch_dshield()
        n_c = sum(1 for r in ds["ips"] if r.get("country"))
        record_health("dshield", True, len(ds["ips"]), detail={**ds["detail"], "with_country": n_c,
                                                                "ports": len(ds["ports"]), "days": len(ds["days"])})
    except Exception as e:
        record_health("dshield", False, error=str(e))
    if os.environ.get("TPOT_ES_URL"):
        try:
            tp = fetch_tpot()
            record_health("tpot", True, sum(n for _, n, _ in tp["src"]))
        except Exception as e:
            record_health("tpot", False, error=str(e))
    if not ds and not tp:
        print("[attackmap] nothing fetched; keeping previous files")
        return
    rows = build_rows(ds, tp)
    hist = load("attackmap.json", {}).get("history", [])
    if ds:
        hist = [h for h in hist if h.get("date") != ds["day"]]
        hist.append({"date": ds["day"], "top_ip_reports": sum(r["reports"] for r in ds["ips"]),
                     "top_ports": [[p["port"], p["records"]] for p in ds["ports"][:5]]})
        hist = sorted(hist, key=lambda h: h["date"])[-60:]
    save("attackmap.json", {"generated": now_iso(), "note": "Sensor observations, not confirmed incidents. "
                            "Source country = country of the network hosting the source IP, not the attacker.",
                            "rows": rows, "history": hist}, pretty=False)
    save("dash/attackmap.json", rows)
    print(f"[attackmap] {len(rows)} rows")
