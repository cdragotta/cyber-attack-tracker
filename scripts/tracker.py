"""Cyber attack tracker data pipeline.

Usage:  python scripts/tracker.py <command> [<command> ...]
Commands: ransomware, alerts, vulns, news, eurepoc, build, all

Each command fetches free public sources, normalizes them and merges them into
data/*.json. A failing source never stops the others; its error is written to
data/sources.json so the dashboard can show it.
"""
import csv
import hashlib
import io
import re
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from common import (all_health, COUNTRY_NAMES, NAME_TO_ISO, clean, days_ago, europe_scope, first, http_get, iso2,
                    is_europe, load, merge_records, now_iso, now_utc, record_health, save, slug, to_date)

RL = "https://api.ransomware.live/v2"


def _as_list(obj, *keys):
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for k in keys + ("data", "items", "results", "victims", "posts"):
            if isinstance(obj.get(k), list):
                return obj[k]
    return []


def _claim_id(group, victim):
    return "claim-" + slug(group, 30) + "-" + slug(victim, 50)


# ===================================================================== ransomware
def _rl_victim(v):
    victim = clean(first(v, "victim", "post_title", "name", "title"), 140)
    group = clean(first(v, "group", "group_name", "gang"), 60)
    cc = iso2(first(v, "country", "country_code"))
    discovered = to_date(first(v, "discovered", "published", "date"))
    return {
        "id": _claim_id(group, victim),
        "date": discovered,
        "attack_date": to_date(first(v, "attackdate", "attack_date", "published")),
        "victim": victim,
        "group": group,
        "country": cc,
        "country_name": COUNTRY_NAMES.get(cc, cc),
        "scope": europe_scope(cc),
        "sector": clean(first(v, "activity", "sector", "industry"), 60) or "Unknown",
        "domain": clean(first(v, "domain", "website"), 80),
        "description": clean(first(v, "description", "summary"), 280),
        "url": first(v, "permalink", "url", "claim_url", "post_url"),
        "status": "claim",
        "seen_in": ["ransomware.live"],
        "first_seen": now_iso(),
    }


def cmd_ransomware():
    claims_new, incidents_new = [], []

    # --- ransomware.live: recent victims + current/previous month (1 req/min per endpoint)
    try:
        today = now_utc()
        prev = today.replace(day=1) - timedelta(days=1)
        rows = _as_list(http_get(f"{RL}/recentvictims"))
        time.sleep(3)
        for y, m in ((today.year, today.month), (prev.year, prev.month)):
            try:
                rows += _as_list(http_get(f"{RL}/victims/{y}/{m:02d}"))
            except Exception as e:  # month endpoint is a bonus
                print("month backfill skipped:", e)
            time.sleep(65)  # same endpoint path family: respect 1 req/min
        for v in rows:
            if isinstance(v, dict):
                c = _rl_victim(v)
                if c["victim"] and c["date"]:
                    claims_new.append(c)
        record_health("ransomware.live", True, len(rows))
    except Exception as e:
        record_health("ransomware.live", False, error=str(e))

    # --- ransomware.live: press-reported cyberattacks (not only ransomware)
    try:
        rows = _as_list(http_get(f"{RL}/recentcyberattacks"))
        for a in rows:
            if not isinstance(a, dict):
                continue
            title = clean(first(a, "title", "victim", "name"), 200)
            if not re.search(r"[A-Za-z]{3}", title):
                title = clean(first(a, "victim", "name", "domain"), 200) or title
            cc = iso2(first(a, "country", "country_code"))
            date = to_date(first(a, "date", "attackdate", "added", "published"))
            if not title or not date:
                continue
            incidents_new.append({
                "id": "inc-" + date + "-" + slug(title, 60),
                "date": date,
                "title": title,
                "victim": clean(first(a, "victim", "name", "domain"), 120),
                "country": cc,
                "country_name": COUNTRY_NAMES.get(cc, cc),
                "scope": europe_scope(cc),
                "summary": clean(first(a, "summary", "description", "text"), 360),
                "url": first(a, "url", "link", "source"),
                "source": "ransomware.live press tracker",
                "status": "reported",
                "first_seen": now_iso(),
            })
        record_health_extra = len(rows)
        print(f"[ransomware.live/cyberattacks] ok records={record_health_extra}")
    except Exception as e:
        print("[ransomware.live/cyberattacks] FAILED", e)

    # --- RansomLook: independent cross-check of recent leak-site posts
    try:
        try:
            posts = _as_list(http_get("https://www.ransomlook.io/api/recent"))
        except Exception:
            posts = _as_list(http_get("https://www.ransomlook.io/api/last/2"))
        known = {c["id"]: c for c in claims_new}
        by_victim = defaultdict(list)
        for c in claims_new:
            by_victim[slug(c["victim"], 50)].append(c)
        added = 0
        for p in posts:
            if not isinstance(p, dict):
                continue
            victim = clean(first(p, "post_title", "victim", "title"), 140)
            group = clean(first(p, "group_name", "group"), 60)
            if not victim:
                continue
            matches = by_victim.get(slug(victim, 50))
            if matches:
                for c in matches:
                    if "ransomlook" not in c["seen_in"]:
                        c["seen_in"].append("ransomlook")
                continue
            cid = _claim_id(group, victim)
            if cid in known:
                continue
            c = {
                "id": cid, "date": to_date(first(p, "discovered", "date")), "attack_date": "",
                "victim": victim, "group": group, "country": "", "country_name": "",
                "scope": "Unknown", "sector": "Unknown", "domain": "",
                "description": clean(first(p, "description"), 280),
                "url": "https://www.ransomlook.io/group/" + group if group else "",
                "status": "claim", "seen_in": ["ransomlook"], "first_seen": now_iso(),
            }
            if c["date"]:
                claims_new.append(c)
                known[cid] = c
                added += 1
        record_health("ransomlook", True, len(posts))
    except Exception as e:
        record_health("ransomlook", False, error=str(e))

    # merge: keep 400 days of claims, 400 days of incidents
    old_claims = load("claims.json", [])
    # keep sources seen earlier
    old_seen = {c["id"]: c.get("seen_in", []) for c in old_claims}
    for c in claims_new:
        for s in old_seen.get(c["id"], []):
            if s not in c["seen_in"]:
                c["seen_in"].append(s)
        # never let a RansomLook-only row erase a richer ransomware.live row
    rich = {c["id"]: c for c in old_claims}
    final_new = []
    for c in claims_new:
        prev = rich.get(c["id"])
        if prev and not c["country"] and prev.get("country"):
            prev["seen_in"] = sorted(set(prev.get("seen_in", []) + c["seen_in"]))
            final_new.append(prev)
        else:
            final_new.append(c)
    save("claims.json", merge_records(old_claims, final_new, keep_days=400))
    save("incidents.json", merge_records(load("incidents.json", []), incidents_new, keep_days=400))


# ===================================================================== alerts
CERT_FEEDS = [
    # (CERT name, ISO-2 / EU, feed URL)
    ("CERT-EU", "EU", "https://cert.europa.eu/publications/threat-intelligence-rss|https://www.cert.europa.eu/publications/threat-intelligence-rss"),
    ("CERT-EU", "EU", "https://cert.europa.eu/publications/security-advisories-rss|https://www.cert.europa.eu/publications/security-advisories-rss"),
    ("CERT-FR", "FR", "https://www.cert.ssi.gouv.fr/feed/"),
    ("UK NCSC", "GB", "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml"),
    ("NCSC NL", "NL", "https://feeds.ncsc.nl/nieuws.rss"),
    ("CCB Belgium", "BE", "https://ccb.belgium.be/advisories.xml|https://ccb.belgium.be/news.xml|https://ccb.belgium.be/en/rss.xml"),
    ("INCIBE-CERT", "ES", "https://www.incibe.es/en/incibe-cert/alerta-temprana/avisos/feed"),
    ("CERT.PL", "PL", "https://cert.pl/en/rss.xml"),
    ("CERT.at", "AT", "https://cert.at/cert-at.en.blog.rss_2.0.xml"),
    ("Swiss NCSC", "CH", "https://www.newsd.admin.ch/newsd/feeds/rss?lang=en&org-nr=1101"),
    ("CERT-UA", "UA", "https://cert.gov.ua/api/articles/rss"),
    ("NCSC-FI", "FI", "https://www.kyberturvallisuuskeskus.fi/feed/rss/en"),
    ("CSIRT Italia", "IT", "https://www.acn.gov.it/portale/feedrss/-/journal/rss/20119/723192"),
    ("CERT.LV", "LV", "https://cert.lv/en/feed/rss/all"),
]


def _strip_ns(tag):
    return tag.split("}", 1)[-1].lower()


def parse_feed(text):
    root = ET.fromstring(text.encode("utf-8") if isinstance(text, str) else text)
    items = []
    for el in root.iter():
        if _strip_ns(el.tag) not in ("item", "entry"):
            continue
        d = {}
        for ch in el:
            t = _strip_ns(ch.tag)
            if t == "link":
                d.setdefault("link", (ch.text or "").strip() or ch.attrib.get("href", ""))
            elif t in ("title", "description", "summary", "content", "pubdate", "published", "updated", "date"):
                d.setdefault(t, ch.text or "")
        items.append(d)
    return items


def cmd_alerts():
    new, ok_feeds, errors, detail = [], 0, [], {}
    browser = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 cyber-attack-tracker"}
    for cert, cc, urls in CERT_FEEDS:
        items, err = None, ""
        for url in urls.split("|"):
            for hdr in (None, browser):
                try:
                    items = parse_feed(http_get(url, as_json=False, timeout=40, retries=0, headers=hdr))
                    break
                except Exception as e:
                    err = f"{url}: {str(e)[:120]}"
            if items is not None:
                break
        key = f"{cert} ({urls.split('|')[0].split('/')[-1] or 'feed'})"
        if items is None:
            errors.append(f"{cert}: {err}")
            detail[key] = "failed: " + err
            continue
        detail[key] = f"ok, {len(items)} items"
        try:
            for it in items[:40]:
                date = to_date(first(it, "pubdate", "published", "updated", "date"))
                title = clean(it.get("title"), 220)
                link = (it.get("link") or "").strip()
                if not title or not date:
                    continue
                new.append({
                    "id": hashlib.sha1((link or title).encode()).hexdigest()[:16],
                    "date": date, "title": title,
                    "summary": clean(first(it, "description", "summary", "content"), 300),
                    "url": link, "cert": cert, "country": cc,
                    "country_name": "European Union" if cc == "EU" else COUNTRY_NAMES.get(cc, cc),
                    "scope": "EU" if cc == "EU" else europe_scope(cc),
                    "first_seen": now_iso(),
                })
            ok_feeds += 1
        except Exception as e:
            errors.append(f"{cert}: {str(e)[:120]}")
    merged = merge_records(load("alerts.json", []), new, keep_days=180)
    save("alerts.json", merged)
    record_health("cert-rss", ok_feeds > 0, len(new),
                  error=(f"{ok_feeds}/{len(CERT_FEEDS)} feeds ok; " + "; ".join(errors)) if errors else "",
                  detail=detail)


# ===================================================================== vulnerabilities
def _euvd_items():
    base = "https://euvdservices.enisa.europa.eu/api"
    since = days_ago(365)
    out = []
    for path in ("search", "vulnerabilities"):
        try:
            for page in range(0, 15):
                d = http_get(f"{base}/{path}?exploited=true&fromDate={since}&size=100&page={page}",
                             timeout=40, retries=1)
                items = _as_list(d)
                out += items
                if len(items) < 100:
                    break
                time.sleep(1)
            if out:
                return out
        except Exception as e:
            print(f"EUVD /{path} failed:", e)
    # last resort: convenience endpoint (small list)
    return _as_list(http_get(f"{base}/exploitedvulnerabilities", timeout=40, retries=1))


def cmd_vulns():
    try:
        kev = http_get("https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json")
        cutoff = days_ago(365)
        rows = [v for v in kev.get("vulnerabilities", []) if v.get("dateAdded", "") >= cutoff]
        record_health("cisa-kev", True, len(rows))
    except Exception as e:
        record_health("cisa-kev", False, error=str(e))
        return

    old = {v["cve"]: v for v in load("vulns.json", [])}
    vulns = []
    for v in rows:
        cve = v["cveID"]
        prev = old.get(cve, {})
        vulns.append({
            "id": cve, "cve": cve, "date": v.get("dateAdded", ""),
            "vendor": v.get("vendorProject", ""), "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""), "description": clean(v.get("shortDescription"), 300),
            "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
            "due": v.get("dueDate", ""), "action": clean(v.get("requiredAction"), 160),
            "epss": prev.get("epss"), "percentile": prev.get("percentile"),
            "euvd_id": prev.get("euvd_id", ""), "euvd_score": prev.get("euvd_score"),
        })

    # EPSS for everything in the window (batched)
    try:
        cves = [v["cve"] for v in vulns]
        scores = {}
        for i in range(0, len(cves), 80):
            d = http_get("https://api.first.org/data/v1/epss?cve=" + ",".join(cves[i:i + 80]), timeout=40)
            for r in d.get("data", []):
                scores[r["cve"]] = (round(float(r["epss"]), 4), round(float(r["percentile"]), 4))
            time.sleep(1)
        for v in vulns:
            if v["cve"] in scores:
                v["epss"], v["percentile"] = scores[v["cve"]]
        record_health("first-epss", True, len(scores))
    except Exception as e:
        record_health("first-epss", False, error=str(e))

    # EUVD IDs for exploited vulns
    try:
        items = _euvd_items()
        m = {}
        for it in items:
            for alias in re.findall(r"CVE-\d{4}-\d+", str(first(it, "aliases", "alias", default=""))):
                m[alias] = (it.get("id", ""), it.get("baseScore"))
        hit = 0
        for v in vulns:
            if v["cve"] in m:
                v["euvd_id"], v["euvd_score"] = m[v["cve"]]
                hit += 1
        record_health("enisa-euvd", bool(items), len(items),
                      error="" if items else "no items returned")
        print(f"EUVD matched {hit} KEV entries")
    except Exception as e:
        record_health("enisa-euvd", False, error=str(e))

    vulns.sort(key=lambda v: (v["date"], v["cve"]), reverse=True)
    save("vulns.json", vulns)


# ===================================================================== news
GDELT_QUERIES = [
    '(cyberattack OR "cyber attack" OR ransomware OR "data breach" OR DDoS OR hackers) sourcelang:english',
    '(cyberattaque OR Cyberangriff OR ciberataque OR cyberaanval OR cyberatak)',
]
_NAME_PATTERNS = sorted(NAME_TO_ISO.items(), key=lambda kv: -len(kv[0]))


def mentioned_countries(text):
    t = " " + (text or "").lower() + " "
    found = []
    for name, cc in _NAME_PATTERNS:
        if len(name) <= 3:
            continue
        if re.search(r"[^a-z]" + re.escape(name) + r"[^a-z]", t) and cc not in found:
            found.append(cc)
    return found[:4]


def cmd_news():
    new, errors = [], []
    try:
        for q in GDELT_QUERIES:
            url = ("https://api.gdeltproject.org/api/v2/doc/doc?mode=artlist&format=json&sort=datedesc"
                   "&maxrecords=250&timespan=2d&query=" + urllib_quote(q))
            try:
                d = http_get(url, timeout=90, retries=1)
            except Exception as e:
                errors.append(str(e)[:250])
                time.sleep(7)
                continue
            for a in d.get("articles", []) if isinstance(d, dict) else []:
                title = clean(a.get("title"), 220)
                if not title:
                    continue
                pub_cc = iso2(a.get("sourcecountry", ""))
                ments = mentioned_countries(title)
                new.append({
                    "id": hashlib.sha1(a.get("url", title).encode()).hexdigest()[:16],
                    "date": to_date(a.get("seendate", "")), "title": title, "url": a.get("url", ""),
                    "domain": a.get("domain", ""), "language": a.get("language", ""),
                    "publisher_country": a.get("sourcecountry", ""),
                    "mentions": ments,
                    "europe": any(is_europe(c) for c in ments) or is_europe(pub_cc),
                    "first_seen": now_iso(),
                })
            time.sleep(7)  # GDELT asks for >= 5 s between requests
        # collapse near-identical headlines
        seen, dedup = set(), []
        for n in new:
            k = slug(n["title"], 70)
            if k not in seen:
                seen.add(k)
                dedup.append(n)
        save("news.json", merge_records(load("news.json", []), dedup, keep_days=14))
        record_health("gdelt", bool(dedup), len(dedup), error=" | ".join(errors))
    except Exception as e:
        record_health("gdelt", False, error=str(e))


def urllib_quote(s):
    from urllib.parse import quote
    return quote(s, safe="")


# ===================================================================== EuRepoC (historical, quarterly)
def cmd_eurepoc():
    try:
        rec = http_get("https://zenodo.org/api/records/14965395")
        files = rec.get("files", [])
        pick = None
        for want in ("main", "global"):
            for f in files:
                k = f.get("key", "").lower()
                if k.endswith(".csv") and want in k and "receiver" not in k and "attribution" not in k and "dyadic" not in k:
                    pick = pick or f
        if not pick:
            pick = next((f for f in files if f.get("key", "").lower().endswith(".csv")), None)
        if not pick:
            raise RuntimeError("no CSV in Zenodo record: " + ", ".join(f.get("key", "") for f in files))
        link = pick.get("links", {}).get("self") or pick.get("links", {}).get("content")
        text = http_get(link, as_json=False, timeout=120)
        reader = csv.DictReader(io.StringIO(text))
        cols = reader.fieldnames or []

        def col(*cands):
            for c in cands:
                for name in cols:
                    if name.lower() == c:
                        return name
            for c in cands:
                for name in cols:
                    if c in name.lower():
                        return name
            return None

        c_name, c_date = col("name", "incident_name"), col("start_date", "start_date_inc")
        c_recv = col("receiver_country", "receiver_country_alpha_2_code")
        c_type, c_init = col("incident_type"), col("initiator_name")
        c_cat = col("receiver_category")
        by_year = defaultdict(lambda: {"europe": 0, "world": 0})
        top_eu, types = Counter(), Counter()
        recent = []
        n = 0
        for row in reader:
            n += 1
            year = (to_date(row.get(c_date, "")) or str(row.get(c_date, ""))[:4])[:4]
            ccs = [iso2(x.strip()) for x in re.split(r"[;,|]", row.get(c_recv, "") or "") if x.strip()]
            eu = any(is_europe(c) for c in ccs)
            if year.isdigit():
                by_year[year]["world"] += 1
                if eu:
                    by_year[year]["europe"] += 1
            for c in ccs:
                if is_europe(c):
                    top_eu[c] += 1
            for t in re.split(r"[;,|]", row.get(c_type, "") or ""):
                if t.strip():
                    types[t.strip()] += 1
            if eu and year >= "2024":
                recent.append({"date": to_date(row.get(c_date, "")), "name": clean(row.get(c_name), 140),
                               "countries": [c for c in ccs if c][:4], "type": clean(row.get(c_type), 80),
                               "initiator": clean(row.get(c_init), 80), "category": clean(row.get(c_cat), 80)})
        recent.sort(key=lambda r: r["date"], reverse=True)
        save("eurepoc_summary.json", {
            "dataset": pick.get("key"), "version": rec.get("metadata", {}).get("version", ""),
            "license": "CC BY-NC 4.0", "rows": n, "columns_used": [c_name, c_date, c_recv, c_type, c_init],
            "all_files": [f.get("key") for f in files], "all_columns": cols,
            "by_year": dict(sorted(by_year.items())),
            "top_europe_countries": top_eu.most_common(15), "types": types.most_common(10),
            "recent_europe": recent[:40], "generated": now_iso(),
        }, pretty=True)
        record_health("eurepoc", True, n)
    except Exception as e:
        record_health("eurepoc", False, error=str(e))


# ===================================================================== dashboard bundle
def _week(d):
    dt = datetime.strptime(d, "%Y-%m-%d")
    return (dt - timedelta(days=dt.weekday())).strftime("%Y-%m-%d")


def cmd_build():
    claims = load("claims.json", [])
    incidents = load("incidents.json", [])
    vulns = load("vulns.json", [])
    alerts = load("alerts.json", [])
    news = load("news.json", [])
    d30, d90 = days_ago(30), days_ago(84)

    weekly = defaultdict(lambda: {"europe": 0, "world": 0})
    for c in claims:
        if c.get("date", "") >= d90 and c.get("date", "") <= now_utc().strftime("%Y-%m-%d"):
            w = _week(c["date"])
            weekly[w]["world"] += 1
            if is_europe(c.get("country", "")):
                weekly[w]["europe"] += 1

    c30 = [c for c in claims if c.get("date", "") >= d30]
    keep = ("id", "date", "victim", "group", "country", "country_name", "scope", "sector", "domain",
            "description", "url", "seen_in")
    bundle = {
        "generated": now_iso(),
        "claims": [{k: c.get(k) for k in keep} for c in c30],
        "incidents": [i for i in incidents if i.get("date", "") >= days_ago(90)][:300],
        "vulns": [v for v in vulns if v.get("date", "") >= days_ago(90)],
        "alerts": [a for a in alerts if a.get("date", "") >= d30][:200],
        "news": news[:150],
        "weekly_claims": [{"week": w, **v} for w, v in sorted(weekly.items())],
        "eurepoc": load("eurepoc_summary.json", None),
        "sources": all_health(),
    }
    save("dashboard.json", bundle)
    # one flat row-file per panel, for dashboards that load datasets separately
    for key in ("claims", "incidents", "vulns", "alerts", "news", "weekly_claims"):
        rows = [{k: (", ".join(v) if isinstance(v, list) else v) for k, v in r.items()} for r in bundle[key]]
        save(f"dash/{key}.json", rows)
    health_rows = [{"source": k, **{f: v.get(f) for f in ("signal", "license", "last_success", "last_attempt", "records", "error", "url")}}
                   for k, v in sorted(bundle["sources"].items())]
    save("dash/sources.json", health_rows)
    eu = bundle["eurepoc"] or {}
    save("dash/eurepoc_years.json", [{"year": y, **v} for y, v in (eu.get("by_year") or {}).items()])
    print(f"dashboard.json: {len(bundle['claims'])} claims, {len(bundle['incidents'])} incidents, "
          f"{len(bundle['vulns'])} vulns, {len(bundle['alerts'])} alerts, {len(bundle['news'])} news")


COMMANDS = {"ransomware": cmd_ransomware, "alerts": cmd_alerts, "vulns": cmd_vulns,
            "news": cmd_news, "eurepoc": cmd_eurepoc, "build": cmd_build}

if __name__ == "__main__":
    args = sys.argv[1:] or ["all"]
    if args == ["all"]:
        args = ["ransomware", "alerts", "vulns", "news", "build"]
    for a in args:
        print(f"== {a}")
        COMMANDS[a]()
