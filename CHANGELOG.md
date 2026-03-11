# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] - 2026-03-11

### Added

- **Web UI** — Dark mode Flask dashboard; run locally with `start.bat` or `python web_app.py`.
- **Bulk scanning** — Upload `.txt`/`.csv`/`.log`/`.ioc` files or paste indicators (hashes, IPs, domains).
- **Multi-API key support** — Add multiple VirusTotal API keys; parallel workers use all keys with per-key rate limiting.
- **Smart quota** — Per-key 4 req/min and daily limit tracking; auto-pause when quota exhausted with resume later.
- **Results cache** — VT results cached for 24h; optional “force rescan” to bypass cache.
- **Resume** — Scan state saved after each indicator; pause and resume without losing progress.
- **Quota check** — “Check Quota” shows daily used/allowed per key before scanning.
- **Input validation** — Auto-detect indicator types, defang IOCs, report rejected/duplicate lines and auto-fixed indicators.
- **XLSX export** — Download styled Excel report with detection details, ratings, and VT links.
- **Port handling** — If default port is busy, app finds a free port (5000–5019) and prints the URL.

### Credits

- Built on [munin](https://github.com/Neo23x0/munin) by [Neo23x0 (Florian Roth)](https://github.com/Neo23x0).

[1.0.0]: https://github.com/smartboy223/vt-bulk-scanner/releases/tag/v1.0.0
