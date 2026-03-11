# VirusTotal Bulk Scanner v1.0.0

First stable release. Web-based bulk scanner for VirusTotal with dark mode UI, multi-key support, caching, and XLSX export.

## Highlights

- **Dark mode web UI** — Run locally with `start.bat` (Windows) or `python web_app.py`
- **Bulk scan** — Upload files or paste hashes, IPs, domains; auto-validation and defanging
- **Multi-API keys** — Add multiple VT keys; parallel workers with per-key rate limiting
- **Cache** — 24h result cache; optional force rescan
- **Resume** — Pause and resume scans; state saved after every indicator
- **XLSX export** — Download styled Excel reports with detection details and VT links

## Quick start

1. Clone the repo and run `start.bat` (or `pip install -r requirements.txt` then `python web_app.py`).
2. Open the URL shown in the terminal.
3. Add your VirusTotal API key(s) and start scanning.

## Requirements

- Python 3.8+
- VirusTotal API key — [Get one](https://www.virustotal.com/gui/my-apikey) (free: 4 req/min, 500/day per key)

## Credits

This project builds on [munin](https://github.com/Neo23x0/munin) by [Neo23x0 (Florian Roth)](https://github.com/Neo23x0).

---

**Full changelog:** [CHANGELOG.md](https://github.com/smartboy223/vt-bulk-scanner/blob/main/CHANGELOG.md)
