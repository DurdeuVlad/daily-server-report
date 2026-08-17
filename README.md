# ⚡ daily-server-report

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![Linux](https://img.shields.io/badge/OS-Linux-green.svg)](https://www.kernel.org/)

Grafana-styled daily IT infrastructure, security telemetry, and power loss health report engine for Linux servers & home labs.

---

## 🌟 Key Features

- **Grafana Dark Aesthetic**: High-contrast, clean dark-mode HTML email panels (`#111217` / `#181b1f`).
- **Power Loss & Dirty Reboot Detection**: Inspects system boot logs (`last reboot`) for ungraceful shutdowns / power outages.
- **Cyber Security & Threat Intel**: Tracks failed SSH authentication attempts (24h), UFW firewall status, and non-loopback listening sockets.
- **Sparkline Disk History**: Calculates historical burn rates and renders live inline SVG sparkline trend graphs in email reports.
- **Actionable AI Fix Cards**: Generates copy-paste prompt cards for AI agents **only** when anomalies occur (container degraded, disk > 85%, power interruption, SSH brute-force attempt).
- **Decoupled Secret Management**: Supports Infisical SSOT Machine Identity or standard environment variables (`RESEND_API_KEY`, `SMTP_*`).

---

## 🚀 CLI Usage

```bash
# Test dry-run without sending email (prints HTML report preview)
daily-server-report --test

# Send live daily report email
daily-server-report --send-now

# Simulate anomaly card rendering for visual testing
daily-server-report --simulate-anomaly
```

---

## ⚙️ Configuration & Environment Variables

Copy `.env.example` to `.env` or set environment variables:

```bash
# Option A: Direct API / SMTP Key
RESEND_API_KEY=your_resend_api_key_here

# Option B: Infisical Secret Manager SSOT (Optional)
INFISICAL_DOMAIN=https://infisical.example.com/api
INFISICAL_CLIENT_ID=your-client-id
INFISICAL_CLIENT_SECRET=your-client-secret
INFISICAL_PROJECT_ID=your-project-id
```

### Probes Customization

Copy `probes.json.example` to `probes.json` to define custom HTTP / service endpoints to monitor:

```bash
cp probes.json.example probes.json
```

---

## 📅 System Cron Schedule

To automate via system cron (e.g. `/etc/cron.d/daily-server-report` running daily at **08:00 AM**):

```cron
0 8 * * * root /usr/local/bin/daily-server-report --send-now >/var/log/daily-server-report.log 2>&1
```

---

## 🐋 Docker & Coolify Deployment

This repository includes a `Dockerfile` and `docker-compose.yml` ready for deployment on Coolify, Portainer, or standard Docker hosts:

```bash
docker compose up -d
```

---

## 🔒 Security Guarantee

This open-source release contains **zero hardcoded credentials, secret keys, or private API tokens**. Secrets are fetched dynamically at runtime via environment variables or secret managers.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
