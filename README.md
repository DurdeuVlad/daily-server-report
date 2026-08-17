# ⚡ daily-server-report

Grafana-styled daily IT, security, and power loss health report engine for `home-server-1` (`dwurdy.com`).

---

## 🌟 Key Features

- **Simplified Grafana Dark Aesthetic**: High-contrast, clean dark-mode HTML email panels (`#111217` / `#181b1f`).
- **Power Loss & Dirty Reboot Detection**: Inspects system boot logs (`last reboot`) for ungraceful shutdowns / power outages.
- **Cyber Security & Threat Intel**: Tracks failed SSH authentication attempts (24h), UFW firewall status, and listening sockets.
- **Actionable AI Fix Prompts**: Generates copy-paste prompt cards for Antigravity **only** when anomalies occur (container degraded, disk > 85%, power interruption, SSH brute-force attempt).
- **Infisical SSOT Integration**: Fetches `resend_api_key` dynamically at runtime via Machine Identity.

---

## 🚀 CLI Usage

```bash
# Test dry-run without sending email
daily-server-report --test

# Send live report to durdeuvladioan@gmail.com
daily-server-report --send-now

# Simulate anomaly card rendering
daily-server-report --simulate-anomaly
```

---

## 📅 System Cron Schedule

Automated via `/etc/cron.d/daily-server-report` running daily at **08:00 AM EEST**:
```cron
0 8 * * * root /usr/local/bin/daily-server-report >/var/log/daily-server-report.log 2>&1
```

---

## 🐋 Coolify Deployment

This repository is ready to be hosted as a Coolify application or container using the provided `Dockerfile` and `docker-compose.yml`.
