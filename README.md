# 🛡️ VirusTotal Bulk Scanner

> **Scan hashes, IPs & domains in bulk — right from your browser.**  
> Dark mode UI · Multi API keys · Smart cache · Pause & resume · Export to Excel · Runs 100% locally.

---

## ✨ What is this?

A **web app** that runs on your machine and talks to VirusTotal’s API. Drop in your IOC list (or paste it), hit *Start*, and get detection results — with **multiple API keys**, **caching**, and **XLSX export**. No data leaves your box except the VT API calls.

**Built on [munin](https://github.com/Neo23x0/munin)** by [Neo23x0 (Florian Roth)](https://github.com/Neo23x0) — we extended it into this VT-focused web scanner and kept the credits front and center. 🙌

---

## 🚀 Quick start

| Step | Do this |
|------|--------|
| 1️⃣ | Double-click **`start.bat`** (Windows) or run `python web_app.py` |
| 2️⃣ | Open the URL the terminal prints (e.g. `http://127.0.0.1:5000`) |
| 3️⃣ | Add your [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) and start scanning |

```bash
pip install -r requirements.txt
python web_app.py   # picks a free port if 5000 is busy
```

---

## 🎯 Features at a glance

| | Feature |
|---|--------|
| 🌙 | **Dark mode** — easy on the eyes |
| 📤 | **Bulk upload** — drop `.txt` / `.csv` or paste indicators |
| 🔑 | **Multi API keys** — parallel workers, per-key rate limits |
| 💾 | **Cache** — reuse VT results (24h), save quota |
| ⏸️ | **Pause & resume** — never lose progress |
| 📊 | **Quota check** — see daily usage before you scan |
| ✅ | **Smart validation** — defangs IOCs, flags dupes & bad lines |
| 📥 | **XLSX export** — one-click Excel report with detections & VT links |
| 🔌 | **Port auto-pick** — if 5000 is busy, uses next free port |

---

## 📸 Screenshots

| 1. Launch | 2. Dashboard | 3. Keys & cache |
|----------|--------------|-----------------|
| ![Start](screenshots/1.jpg) | ![Dashboard](screenshots/2.jpg) | ![Keys](screenshots/3.jpg) |

| 4. Upload & validate | 5. Scan running | 6. Results & export |
|----------------------|-----------------|---------------------|
| ![Upload](screenshots/4.jpg) | ![Progress](screenshots/5.jpg) | ![Results](screenshots/6.jpg) |

---

## 📋 Supported indicators

| Type | Example |
|------|--------|
| MD5 | `44d88612fea8a8f36de82e1278abb02f` |
| SHA1 | `3395856ce81f2b7382dee72602f798b642f14140` |
| SHA256 | `e3b0c44298fc1c149afbf4c8996fb924...` |
| IPv4 | `8.8.8.8` |
| Domain | `example.com` |

Defanged stuff (`hxxp://`, `[.]`, etc.) is auto-cleaned. 🧹

---

## ⚙️ Requirements

- **Python 3.8+**
- **VirusTotal API key** — [get one](https://www.virustotal.com/gui/my-apikey) (free: 4 req/min, 500/day per key)

---

## 📁 Repo layout

```
├── web_app.py          # Flask app
├── scanner_engine.py   # VT API, cache, workers
├── start.bat           # Windows one-click run
├── templates/          # UI (base, index, scan)
├── static/images/      # Logo, etc.
├── screenshots/        # README images
└── data/               # Created at run (config, cache, scans) — gitignored
```

---

## 🙏 Credits

This project is based on **[munin](https://github.com/Neo23x0/munin)** by **[Neo23x0 (Florian Roth)](https://github.com/Neo23x0)**. We turned it into this web-based VT bulk scanner (multi-key, cache, resume, XLSX). All kudos to the original repo.

---

**License:** MIT · See [LICENSE](LICENSE) and [CHANGELOG](CHANGELOG.md).
