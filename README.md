# Cyber Attack Tracker

A Europe-first, worldwide tracker of cyberattacks built only from free public sources. GitHub Actions fetch the feeds on a schedule and commit clean JSON to `data/`. A Claude artifact dashboard reads `data/dashboard.json`.

Personal, non-commercial project.

## What's tracked

Four kinds of signal, kept separate. They are never added into one "attack count".

| Signal | File | Sources | Refresh |
| --- | --- | --- | --- |
| Ransomware leak-site **claims** (unconfirmed) | `data/claims.json` | [Ransomware.live](https://www.ransomware.live) v2 API, [RansomLook](https://www.ransomlook.io) | Every 2 h |
| Press-**reported** cyberattacks | `data/incidents.json` | Ransomware.live press tracker | Every 2 h |
| Official **alerts** | `data/alerts.json` | CERT-EU + 13 national CERT RSS feeds ([list](https://github.com/pulsedive/certrss)) | Every 2 h |
| Exploited **vulnerabilities** | `data/vulns.json` | [CISA KEV](https://github.com/cisagov/kev-data), [FIRST EPSS](https://www.first.org/epss), [ENISA EUVD](https://euvd.enisa.europa.eu) | Daily |
| News discovery | `data/news.json` | [GDELT DOC 2.0](https://www.gdeltproject.org) | Every 2 h |
| **Attack map** (sensor observations) | `data/attackmap.json` | [SANS ISC / DShield](https://isc.sans.edu) API (keyless); optionally your own [T-Pot](https://github.com/telekom-security/tpotce) honeypot | Daily |
| History (2000–2024) | `data/eurepoc_summary.json` | [EuRepoC](https://eurepoc.eu) Global Dataset (CC BY-NC 4.0) | Quarterly |

`data/dashboard.json` bundles the last 30–90 days for the dashboard. `data/sources.json` records each source's last success, record count, error and license.

## Attack map

The dashboard's **Attack map** tab is inspired by the [T-Pot Attack Map](https://github.com/telekom-security/t-pot-attack-map) by Deutsche Telekom Security (GPL-3.0). No T-Pot code is used here: the fetcher (`scripts/attackmap.py`) and the map are written from scratch, borrowing only the idea (arcs from source locations, top sources, top ports) and T-Pot's event shape (source country/IP, destination, port, service, count, date).

The T-Pot map only shows events from a honeypot you run yourself, so by default the tab uses public telemetry from the **SANS Internet Storm Center / DShield** sensor network instead:

- `sources/attacks/100/<yesterday>`: the 100 busiest scanning/attacking IPs reported by DShield sensors.
- `ip/<ip>`: the country and AS name of the network hosting each of the top 40 (cached 30 days in `data/attackmap_ipcache.json`).
- `topports/records/20/<yesterday>`: the most-targeted ports. `dailysummary`: daily totals for two weeks.

Caveats, also shown on the page:

- These are **sensor observations** (mostly automated scanning and brute-force traffic), not confirmed incidents, and are never added to the other counts.
- **Source country = where the source IP's network is registered**, not where the attacker is (VPNs, proxies, cloud hosts and botnets hide that).
- DShield does not publish where its sensors are, so the arcs end at the dashboard's Europe focus point, not at a real target.
- Country totals cover only the top 40 source IPs, not all traffic.

Plug in your own T-Pot later: add repository secrets `TPOT_ES_URL` (its Elasticsearch, e.g. `https://my-tpot:64298`) and, if needed, `TPOT_ES_USER` / `TPOT_ES_PASS`. The daily job then also aggregates the last 24 h of events (source country → honeypot country, IPs, ports) as rows with `source: "tpot"`. It is skipped when the secret is unset. The Elasticsearch must be reachable from GitHub's runners (or run `TPOT_ES_URL=... python scripts/tracker.py attackmap` on your own machine and push). This path is untested until a T-Pot exists.

## Translation

Titles, summaries and descriptions in other languages are machine-translated into English on the GitHub runner with open-source [Argos Translate](https://www.argosopentech.com) models (no API key; no text leaves GitHub). Each translated field keeps the original in `<field>_original` and its language in `<field>_lang`. Translations are cached in `data/translations.json`.

## Rules the data follows

- **Country = victim country**, never attacker IP.
- **Europe** = EU27 + UK + wider Europe (CH, NO, IS, UA, MD, Western Balkans, TR, Caucasus, microstates).
- A ransomware leak-site post stays `status: claim`, however often it is repeated.
- News `mentions` are countries named in the headline, not confirmed victims.

## Run locally

```bash
python scripts/tracker.py all        # ransomware, alerts, vulns, news, build
python scripts/tracker.py eurepoc build
```

Python 3.10+, standard library only. Workflows can be run by hand from the Actions tab.

## Licensing

SANS ISC / DShield data is free to use with attribution ("Data provided by SANS Internet Storm Center"). Ransomware.live's free v2 API is for personal use only. EuRepoC data is CC BY-NC 4.0. CISA KEV is CC0. RansomLook content is CC BY 4.0. Check each source's terms before any commercial use.

## Dashboard

The live dashboard is a Claude artifact, **Europe Cyber Watch**. A daily scheduled task (06:33 UTC) copies `data/dash/*.json` into it. `dashboard/index.html` is a copy of its page code for safekeeping.
