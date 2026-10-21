"""Shared helpers: HTTP, JSON files, dates, Europe tagging, source health."""
import gzip
import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
UA = "cyber-attack-tracker/1.0 (+https://github.com/cdragotta/cyber-attack-tracker)"

# ---------------------------------------------------------------- geography
EU27 = set("AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE".split())
UK = {"GB"}
WIDER_EUROPE = set("CH NO IS LI UA MD RS BA ME MK AL XK GE AM AZ TR AD MC SM VA".split())

COUNTRY_NAMES = {
    "AT": "Austria", "BE": "Belgium", "BG": "Bulgaria", "HR": "Croatia", "CY": "Cyprus",
    "CZ": "Czechia", "DK": "Denmark", "EE": "Estonia", "FI": "Finland", "FR": "France",
    "DE": "Germany", "GR": "Greece", "HU": "Hungary", "IE": "Ireland", "IT": "Italy",
    "LV": "Latvia", "LT": "Lithuania", "LU": "Luxembourg", "MT": "Malta", "NL": "Netherlands",
    "PL": "Poland", "PT": "Portugal", "RO": "Romania", "SK": "Slovakia", "SI": "Slovenia",
    "ES": "Spain", "SE": "Sweden", "GB": "United Kingdom", "CH": "Switzerland", "NO": "Norway",
    "IS": "Iceland", "LI": "Liechtenstein", "UA": "Ukraine", "MD": "Moldova", "RS": "Serbia",
    "BA": "Bosnia and Herzegovina", "ME": "Montenegro", "MK": "North Macedonia", "AL": "Albania",
    "XK": "Kosovo", "GE": "Georgia", "AM": "Armenia", "AZ": "Azerbaijan", "TR": "Turkey",
    "AD": "Andorra", "MC": "Monaco", "SM": "San Marino", "VA": "Vatican City",
    "US": "United States", "CA": "Canada", "MX": "Mexico", "BR": "Brazil", "AR": "Argentina",
    "CL": "Chile", "CO": "Colombia", "PE": "Peru", "AU": "Australia", "NZ": "New Zealand",
    "JP": "Japan", "KR": "South Korea", "CN": "China", "TW": "Taiwan", "HK": "Hong Kong",
    "IN": "India", "PK": "Pakistan", "ID": "Indonesia", "MY": "Malaysia", "SG": "Singapore",
    "TH": "Thailand", "VN": "Vietnam", "PH": "Philippines", "IL": "Israel", "AE": "UAE",
    "SA": "Saudi Arabia", "QA": "Qatar", "EG": "Egypt", "ZA": "South Africa", "NG": "Nigeria",
    "KE": "Kenya", "MA": "Morocco", "RU": "Russia", "BY": "Belarus", "IR": "Iran",
}
NAME_TO_ISO = {v.lower(): k for k, v in COUNTRY_NAMES.items()}
NAME_TO_ISO.update({"uk": "GB", "united kingdom": "GB", "britain": "GB", "england": "GB",
                    "usa": "US", "united states of america": "US", "czech republic": "CZ",
                    "the netherlands": "NL", "holland": "NL", "türkiye": "TR", "turkiye": "TR",
                    "south korea": "KR", "korea": "KR", "russian federation": "RU"})


def iso2(value):
    """Best-effort ISO-2 code from a code or a country name."""
    if not value:
        return ""
    v = str(value).strip()
    if len(v) == 2 and v.isalpha():
        v = v.upper()
        return "GB" if v == "UK" else v
    return NAME_TO_ISO.get(v.lower(), "")


def europe_scope(cc):
    if cc in EU27:
        return "EU27"
    if cc in UK:
        return "UK"
    if cc in WIDER_EUROPE:
        return "Wider Europe"
    return "Non-Europe" if cc else "Unknown"


def is_europe(cc):
    return europe_scope(cc) in ("EU27", "UK", "Wider Europe")


# ---------------------------------------------------------------- dates
def now_utc():
    return datetime.now(timezone.utc)


def now_iso():
    return now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")


_DATE_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d", "%a, %d %b %Y %H:%M:%S %z",
    "%a, %d %b %Y %H:%M:%S %Z", "%b %d, %Y, %I:%M:%S %p", "%Y%m%dT%H%M%SZ", "%d/%m/%Y",
]


def to_date(value):
    """Return YYYY-MM-DD for many date spellings, or '' if unparseable."""
    if not value:
        return ""
    s = str(value).strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
    return "-".join(m.groups()) if m else ""


def days_ago(n):
    return (now_utc() - timedelta(days=n)).strftime("%Y-%m-%d")


# ---------------------------------------------------------------- http
def http_get(url, *, as_json=True, timeout=60, retries=2, headers=None, method="GET", body=None):
    h = {"User-Agent": UA, "Accept": "application/json, application/xml, text/xml, */*"}
    if headers:
        h.update(headers)
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=h, method=method, data=body)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                if r.headers.get("Content-Encoding") == "gzip" or raw[:2] == b"\x1f\x8b":
                    raw = gzip.decompress(raw)
                text = raw.decode("utf-8", errors="replace")
                return json.loads(text) if as_json else text
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ConnectionError) as e:
            last = e
            if isinstance(e, urllib.error.HTTPError) and e.code in (400, 401, 403, 404):
                break
            time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"GET {url} failed: {last}")


# ---------------------------------------------------------------- files
def load(name, default):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return default


def save(name, obj, pretty=False):
    path = os.path.join(DATA, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        if pretty:
            json.dump(obj, f, ensure_ascii=False, indent=1)
        else:
            json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
        f.write("\n")


def merge_records(old, new, key="id", date_field="date", keep_days=None):
    """Merge by id (new wins), drop records older than keep_days, newest first."""
    by_id = {r[key]: r for r in old if r.get(key)}
    for r in new:
        if r.get(key):
            prev = by_id.get(r[key], {})
            # keep first-seen time stable
            if prev.get("first_seen"):
                r["first_seen"] = prev["first_seen"]
            by_id[r[key]] = r
    out = list(by_id.values())
    if keep_days:
        cutoff = days_ago(keep_days)
        out = [r for r in out if (r.get(date_field) or "9999") >= cutoff]
    out.sort(key=lambda r: (r.get(date_field) or "", r.get(key)), reverse=True)
    return out


def slug(text, n=60):
    s = re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-")
    return s[:n] or "x"


def clean(text, n=400):
    s = re.sub(r"<[^>]+>", " ", str(text or ""))
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def first(d, *keys, default=""):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return v
    return default


# ---------------------------------------------------------------- source health
SOURCE_META = {
    "ransomware.live": {"url": "https://www.ransomware.live", "license": "Free v2 API, personal use only", "signal": "Ransomware claims + reported attacks"},
    "ransomlook": {"url": "https://www.ransomlook.io", "license": "CC BY 4.0", "signal": "Ransomware claims (cross-check)"},
    "cisa-kev": {"url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "license": "CC0", "signal": "Exploited vulnerabilities"},
    "enisa-euvd": {"url": "https://euvd.enisa.europa.eu", "license": "ENISA public service", "signal": "EU vulnerability IDs"},
    "first-epss": {"url": "https://www.first.org/epss", "license": "Free, no registration", "signal": "Exploit probability"},
    "cert-rss": {"url": "https://github.com/pulsedive/certrss", "license": "Public RSS (official CERTs)", "signal": "Official alerts"},
    "gdelt": {"url": "https://www.gdeltproject.org", "license": "Free, open", "signal": "News discovery"},
    "eurepoc": {"url": "https://eurepoc.eu", "license": "CC BY-NC 4.0 (non-commercial)", "signal": "Historical coded incidents"},
}


def record_health(source, ok, count=0, error=""):
    health = load("sources.json", {})
    entry = health.get(source, {})
    entry.update(SOURCE_META.get(source, {}))
    entry["last_attempt"] = now_iso()
    if ok:
        entry["last_success"] = now_iso()
        entry["records"] = count
        entry["error"] = ""
    else:
        entry["error"] = clean(error, 300)
    health[source] = entry
    save("sources.json", health, pretty=True)
    status = "ok" if ok else "FAILED"
    print(f"[{source}] {status} records={count} {error}")
