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
| History (2000–2024) | `data/eurepoc_summary.json` | [EuRepoC](https://eurepoc.eu) Global Dataset (CC BY-NC 4.0) | Quarterly |

`data/dashboard.json` bundles the last 30–90 days for the dashboard. `data/sources.json` records each source's last success, record count, error and license.

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

Ransomware.live's free v2 API is for personal use only. EuRepoC data is CC BY-NC 4.0. CISA KEV is CC0. RansomLook content is CC BY 4.0. Check each source's terms before any commercial use.
