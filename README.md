# LeakRadar

<img width="1536" height="672" alt="js27lqmk6s1h3507m7yz" src="https://github.com/user-attachments/assets/bef181e6-71c9-4a0d-976a-e98be64a4a0e" />

An open-source **credential exposure monitoring** system built with Python and OSINT principles. It continuously checks email addresses against breach databases (Have I Been Pwned and more) and alerts you via **Telegram**, **Discord**, and **Email** when new data breaches are detected.

> 📖 **Read the full article:** https://dev.to/ismail-benali/how-to-build-an-advanced-data-breach-monitoring-system-with-osint-and-python-leakradar-5j1
> "How to Build an Advanced Data Breach Monitoring System with OSINT and Python — LeakRadar"
---

## Table of Contents

- [Read the Article](#read-the-article)
- [Features](#features)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Docker Deployment](#docker-deployment)
- [GitHub Actions (Scheduled Scans)](#github-actions-scheduled-scans)
- [Running Tests](#running-tests)
- [Optional Extras](#optional-extras)
- [Security & Ethics](#security--ethics)
- [Roadmap](#roadmap)
- [References](#references)
- [License](#license)

---

## Read the Article

> **📖 Full article:** [How to Build an Advanced Data Breach Monitoring System with OSINT and Python — LeakRadar](https://dev.to/ismail-benali/how-to-build-an-advanced-data-breach-monitoring-system-with-osint-and-python-leakradar-5j1)
>
> 🔗 **[Read it on dev.to](https://dev.to/ismail-benali/how-to-build-an-advanced-data-breach-monitoring-system-with-osint-and-python-leakradar-5j1)**

---

## Features

- **Scheduled monitoring** — scan one or more emails every hour
- **Smart API queries** — integrates trusted breach intelligence APIs (HIBP, DeHashed)
- **Data normalization** — unifies records, extracts domains, classifies exposed data
- **Deduplication** — ignores breaches already seen in previous scans
- **Instant alerts** — notifications over Telegram, Discord, and SMTP email
- **Risk scoring** — each breach gets a 0–100 risk score and a severity rating
- **Persistent logging** — all events recorded with rotating log files
- **Local storage** — SQLite database with zero external dependencies
- **Deployable** — Docker, Docker Compose, and GitHub Actions ready

---

## How It Works

Breach monitoring services like LeakRadar work in four stages:

1. **Data collection** — researchers gather leaks from dark web markets, paste sites, leak databases, and honeypots.
2. **Processing** — raw records are cleaned and normalized into a standard format.
3. **Indexing** — data is stored in fast-searchable databases.
4. **Querying** — services expose APIs so anyone can check whether an account appears in a breach.

This project consumes those APIs (via OSINT) to deliver a **credential exposure monitoring** service: it queries the breach databases for the emails you own and notifies you when your data shows up.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Scheduler (Cron)                       │
│                   Runs every 1 hour                         │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Breach Intelligence APIs Layer                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │     HIBP     │  │   DeHashed   │  │  BreachDir   │      │
│  │     API      │  │     API      │  │     API      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                   Data Normalizer                           │
│  - Cleans data                                              │
│  - Standardizes formats                                     │
│  - Extracts domains                                         │
│  - Classifies exposed data types                            │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Duplicate Check & Storage                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   SQLite     │  │    Redis     │  │  PostgreSQL  │      │
│  │   Cache      │  │    Cache     │  │  (Optional)  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└──────────────────────┬──────────────────────────────────────┘
                       │
            New Leak?  │
          ┌────────────┴────────────┐
          │                         │
         No                        Yes
          │                         │
          ▼                         ▼
   Wait Next Scan           ┌─────────────────┐
                            │  Alert Engine   │
                            └────────┬────────┘
                                     │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
  ┌───────────┐               ┌──────────────┐             ┌──────────────┐
  │ Telegram  │               │   Discord    │             │    Email     │
  │   Bot     │               │  Webhook     │             │    SMTP      │
  └───────────┘               └──────────────┘             └──────────────┘
```

---

## Project Structure

```
leakradar/
├── src/
│   ├── __init__.py
│   ├── config.py              # System configuration
│   ├── models.py              # Data models (Breach, BreachCheckResult)
│   ├── breach_api.py          # HIBP / DeHashed API clients
│   ├── async_breach_api.py    # Async API client (optional)
│   ├── normalizer.py          # Data normalization & risk scoring
│   ├── storage.py             # SQLite storage layer
│   ├── cache.py               # Redis caching layer (optional)
│   ├── alerting.py            # Telegram / Discord / Email alerts
│   ├── scheduler.py           # Scheduling & orchestration
│   ├── security.py            # Ownership validation & audit logging
│   └── main.py                # Entry point
├── tests/
│   ├── test_breach_api.py
│   ├── test_normalizer.py
│   └── test_storage.py
├── data/
│   ├── leaks.db               # SQLite database (gitignored)
│   └── logs/                  # Log files (gitignored)
├── .env.example               # Example environment file
├── .gitignore
├── requirements.txt
├── requirements-dev.txt       # Test & optional extras
├── Dockerfile
├── docker-compose.yml
├── .github/
│   └── workflows/
│       └── scheduled-scan.yml
└── README.md
```

---

## Quick Start

### 1. Prerequisites

- Python 3.11+
- A Have I Been Pwned API key — [get one here](https://haveibeenpwned.com/API/Key)

### 2. Clone & install

```bash
git clone https://github.com/Ismail-Benali/LeakRadar.git
cd leakradar

python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure

```bash
cp .env.example .env
```

Edit `.env` and set at least:

```ini
TARGET_EMAILS=you@example.com
HIBP_API_KEY=your_key_here
```

### 4. Run

```bash
python -m src.main
```

The first scan runs immediately, then repeats every `SCAN_INTERVAL_HOURS` (default 1 hour).

---

## Configuration

All settings are read from environment variables (see `.env.example`).

| Variable                | Description                              | Default                         |
| ----------------------- | ---------------------------------------- | ------------------------------- |
| `TARGET_EMAILS`         | Comma-separated emails to monitor        | —                               |
| `HIBP_API_KEY`          | Have I Been Pwned API key                | —                               |
| `HIBP_API_URL`          | HIBP API base URL                        | `https://haveibeenpwned.com/api/v3` |
| `TELEGRAM_BOT_TOKEN`    | Telegram bot token (optional)            | —                               |
| `TELEGRAM_CHAT_ID`      | Telegram chat id (optional)              | —                               |
| `DISCORD_WEBHOOK_URL`   | Discord webhook URL (optional)           | —                               |
| `SMTP_SERVER`           | SMTP server (optional)                   | —                               |
| `SMTP_PORT`             | SMTP port                                | `587`                           |
| `SMTP_USERNAME`         | SMTP username (optional)                 | —                               |
| `SMTP_PASSWORD`         | SMTP password (optional)                 | —                               |
| `SMTP_FROM`             | Sender email (optional)                  | —                               |
| `SMTP_TO`               | Recipient email (optional)               | —                               |
| `DATABASE_URL`          | SQLite location                          | `sqlite:///data/leaks.db`       |
| `LOG_LEVEL`             | `DEBUG` / `INFO` / `WARNING` / `ERROR`   | `INFO`                          |
| `LOG_FILE`              | Log file path                            | `data/logs/leakradar.log`       |
| `SCAN_INTERVAL_HOURS`   | Hours between scans                      | `1`                             |
| `MAX_RETRIES`           | HTTP retry attempts                      | `3`                             |
| `REQUEST_TIMEOUT`       | HTTP timeout in seconds                  | `30`                            |

At least one alert channel (Telegram, Discord, or Email) is recommended; otherwise alerts are simply logged.

---

## Docker Deployment

```bash
# Build and start the monitor plus optional Redis
docker compose up -d --build

# Follow the logs
docker logs -f leakradar

# Stop
docker compose down
```

The `data/` directory is mounted so the SQLite database and logs persist across container restarts.

---

## GitHub Actions (Scheduled Scans)

You can run scans from GitHub for free without hosting a server.

1. Push this repository to GitHub.
2. In **Settings → Secrets and variables → Actions**, add the following repository secrets:
   - `TARGET_EMAILS`, `HIBP_API_KEY`
   - `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` (optional)
   - `DISCORD_WEBHOOK_URL` (optional)
   - `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO` (optional)
3. The `scheduled-scan.yml` workflow runs every hour and can also be triggered manually from the **Actions** tab.

> **Important:** Never commit real secrets. Only the `.env.example` template should be committed.

---

## Running Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Tests cover the API client, the normalizer (including risk scoring), and the SQLite storage layer.

---

## Optional Extras

- **`src/async_breach_api.py`** — parallel async checks with `aiohttp` for better performance at scale.
- **`src/cache.py`** — Redis-backed caching of API responses to reduce rate-limit pressure.
- **Web dashboard** — a FastAPI dashboard can be added to visualize recent breaches and stats.
- **DeHashed** — plug in `DeHashedAPI` in `breach_api.py` for richer breach data.

---

## Security & Ethics

### Guiding principles

1. **Legality** — only scan accounts you own or are explicitly authorized to monitor.
2. **Consent** — never use this tool to collect data on others without explicit permission.
3. **Secret hygiene** — never commit API keys or upload them to public repositories.
4. **Terms of service** — respect the terms of all API providers.
5. **Compliance** — follow data-protection laws such as GDPR and CCPA.

### Best practices

- Keep `.env` out of version control (already in `.gitignore`).
- Use the `SecurityManager` in `src/security.py` to restrict scanning to owned domains.
- Enable 2FA everywhere you can.

---

## Roadmap

**Phase 1 — Core (complete)**
- [x] Email breach monitoring in LeakRadar
- [x] HIBP API integration
- [x] Multi-channel alerts
- [x] Local storage
- [x] Docker deployment

**Phase 2 — Enhancements**
- [ ] Additional OSINT sources (DeHashed, LeakCheck)
- [ ] GitHub secret scanning for exposed credentials
- [ ] GitLab and Gists support
- [ ] Automatic triage of new breaches
- [ ] Async performance improvements

**Phase 3 — Full platform**
- [ ] Advanced web dashboard
- [ ] Multi-user support with roles
- [ ] Multi-domain management
- [ ] Periodic PDF reports
- [ ] Advanced risk scoring
- [ ] SIEM integrations (Splunk, ELK)

**Phase 4 — Intelligence**
- [ ] Sentiment analysis of leaks
- [ ] Breach prediction
- [ ] Automatic threat classification
- [ ] Intelligent remediation recommendations

---

## References

1. [Have I Been Pwned API Documentation](https://haveibeenpwned.com/API/v3)
2. [OSINT Framework](https://osintframework.com/)
3. [MITRE ATT&CK Framework](https://attack.mitre.org/)
4. [Python Security Best Practices](https://python-security.readthedocs.io/)
5. [OWASP Top 10](https://owasp.org/www-project-top-ten/)
6. [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## License

This project is provided for educational and legitimate security-monitoring purposes. Use it responsibly and only on systems you own or are authorized to test.
