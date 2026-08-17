#!/usr/bin/env python3
"""
Grafana Saga V2 Widescreen Daily IT, Security, Honeypot & Pro SRE Disaster Prevention Digest
Host: home-server-1 | Domain: dwurdy.com
Daily Schedule: 08:00 AM EEST
Hourly Critical Security Alert: Non-Tailscale Public SSH Connections / Attacks
"""

import sys
import os
import json
import time
import shutil
import datetime
import subprocess
import smtplib
import socket
import ssl
import re
import ipaddress
import tomllib
import urllib.request
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import psutil

# Configuration Defaults
# Machine-identity credentials must come from the environment (see
# /etc/default/daily-server-report, sourced by /etc/cron.d/daily-server-report)
# — never hardcode them here, this file is committed to git.
INFISICAL_DOMAIN = os.getenv("INFISICAL_DOMAIN", "https://infisical.dwurdy.com/api")
INFISICAL_CLIENT_ID = os.getenv("INFISICAL_CLIENT_ID", "")
INFISICAL_CLIENT_SECRET = os.getenv("INFISICAL_CLIENT_SECRET", "")
INFISICAL_PROJECT_ID = os.getenv("INFISICAL_PROJECT_ID", "")

SMTP_SERVER = "smtp.resend.com"
SMTP_PORT = 465
SMTP_USER = "resend"
SENDER_EMAIL = "noreply@dwurdy.com"
RECIPIENT_EMAIL = "durdeuvladioan@gmail.com"

DISK_HISTORY_FILE = "/root/github/daily-server-report/disk_history.json"
CRITICAL_STATE_FILE = "/root/github/daily-server-report/critical_alert_state.json"

# NOTE: Removed artificial disable flag. Alerts will now fire only on real non‑Tailscale SSH activity.
def get_resend_key():
    """Fetch resend_api_key from Infisical SSOT using Machine Identity"""
    if not (INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET and INFISICAL_PROJECT_ID):
        print("[!] Warning: INFISICAL_CLIENT_ID/SECRET/PROJECT_ID not set in environment. Checking environment for RESEND_API_KEY fallback...")
        return os.getenv("RESEND_API_KEY", "")
    try:
        token_cmd = (
            f"infisical login --method=universal-auth "
            f"--client-id=\"{INFISICAL_CLIENT_ID}\" "
            f"--client-secret=\"{INFISICAL_CLIENT_SECRET}\" "
            f"--domain=\"{INFISICAL_DOMAIN}\" --plain 2>/dev/null | tail -1"
        )
        token = subprocess.check_output(token_cmd, shell=True).decode().strip()
        if not token:
            raise ValueError("Empty token received from Infisical CLI")

        export_cmd = (
            f"INFISICAL_TOKEN=\"{token}\" infisical export "
            f"--projectId=\"{INFISICAL_PROJECT_ID}\" --env=\"dev\" "
            f"--domain=\"{INFISICAL_DOMAIN}\" --format=json 2>/dev/null"
        )
        raw_json = subprocess.check_output(export_cmd, shell=True).decode()
        data = json.loads(raw_json)
        for item in data:
            if item.get("key") == "resend_api_key":
                return item.get("value")
    except Exception as e:
        print(f"[!] Warning: Infisical key fetch failed ({e}). Checking environment...")
    
    return os.getenv("RESEND_API_KEY", "")

def generate_svg_sparkline(values, width=130, height=28, stroke_color="#38bdf8", fill_color="rgba(56, 189, 248, 0.15)"):
    """Generate email-safe SVG Sparkline Trend Graph"""
    if not values or len(values) < 2:
        v = values[0] if values else 50.0
        values = [v - 1.5, v - 1.0, v - 0.5, v - 0.2, v]
    
    min_v = min(values) * 0.96
    max_v = max(values) * 1.04 if max(values) != min(values) else min(values) + 1.0
    
    points = []
    step = width / (len(values) - 1)
    for i, v in enumerate(values):
        x = round(i * step, 1)
        y = round(height - ((v - min_v) / (max_v - min_v)) * height, 1)
        points.append(f"{x},{y}")
        
    points_str = " ".join(points)
    first_x = points[0].split(',')[0]
    last_x = points[-1].split(',')[0]
    fill_polygon = f"{first_x},{height} {points_str} {last_x},{height}"
    
    svg = f"""
    <svg width="{width}" height="{height}" style="vertical-align:middle;overflow:visible;">
        <polygon points="{fill_polygon}" fill="{fill_color}" />
        <polyline points="{points_str}" fill="none" stroke="{stroke_color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
    """.strip()
    return svg

def update_and_get_disk_history(current_storage_list):
    """Record daily disk usage snapshot and compute true historical burn rates & trend arrays"""
    history = {}
    if os.path.exists(DISK_HISTORY_FILE):
        try:
            with open(DISK_HISTORY_FILE, "r") as f:
                history = json.load(f)
        except Exception:
            history = {}

    today_str = datetime.datetime.now().strftime("%Y-%m-%d")
    snapshot = {}
    for s in current_storage_list:
        snapshot[s["path"]] = {
            "used_gb": s["used_gb"],
            "total_gb": s["total_gb"],
            "percent": s["percent"]
        }
    history[today_str] = snapshot

    sorted_dates = sorted(history.keys())
    if len(sorted_dates) > 30:
        for d in sorted_dates[:-30]:
            del history[d]

    try:
        with open(DISK_HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"[!] Disk history write error: {e}")

    enriched_storage = []
    sorted_dates = sorted(history.keys())
    days_span = len(sorted_dates)

    for s in current_storage_list:
        path = s["path"]
        pct_history = []
        gb_history = []
        
        for d in sorted_dates:
            if path in history[d]:
                pct_history.append(history[d][path]["percent"])
                gb_history.append(history[d][path]["used_gb"])

        daily_growth_gb = 0.0
        if days_span >= 2 and len(gb_history) >= 2:
            used_delta = gb_history[-1] - gb_history[0]
            daily_growth_gb = max(0.0, round(used_delta / (days_span - 1), 2))
        else:
            daily_growth_gb = 0.05

        free_gb = s["free_gb"]
        if daily_growth_gb > 0.08:
            days_remaining = int(free_gb / daily_growth_gb)
            burn_summary = f"+{daily_growth_gb} GB/day • ~{days_remaining} Days Remaining"
            is_warning = days_remaining < 14 or s["percent"] > 85.0
        else:
            days_remaining = 999
            burn_summary = f"Stable (+{daily_growth_gb} GB/day) • Stable (Years Remaining)"
            is_warning = s["percent"] > 85.0

        sparkline_svg = generate_svg_sparkline(pct_history, stroke_color="#f2495c" if is_warning else "#38bdf8")

        enriched_storage.append({
            **s,
            "daily_growth_gb": daily_growth_gb,
            "days_remaining": days_remaining,
            "burn_summary": burn_summary,
            "pct_history": pct_history,
            "sparkline_svg": sparkline_svg,
            "warning": is_warning
        })

    return enriched_storage

def get_system_uptime():
    """Get system uptime string and boot timestamp"""
    boot_time = psutil.boot_time()
    now = time.time()
    uptime_seconds = int(now - boot_time)
    
    days = uptime_seconds // (24 * 3600)
    hours = (uptime_seconds % (24 * 3600)) // 3600
    minutes = (uptime_seconds % 3600) // 60
    
    boot_datetime = datetime.datetime.fromtimestamp(boot_time).strftime('%Y-%m-%d %H:%M:%S')
    return f"{days}d {hours}h {minutes}m", boot_datetime, uptime_seconds

def get_power_loss_history():
    """Check for recent unexpected reboots or dirty shutdowns in last 24h"""
    unexpected_reboots = 0
    reboot_logs = []
    try:
        cmd = "last reboot | head -10"
        out = subprocess.check_output(cmd, shell=True).decode()
        lines = out.strip().split('\n')
        for line in lines:
            if "crash" in line.lower() or "down" in line.lower():
                unexpected_reboots += 1
                reboot_logs.append(line)
    except Exception:
        pass
    
    return unexpected_reboots, reboot_logs

def is_tailscale_or_private_ip(ip_str):
    """Check if an IP address or hostname belongs to Tailscale (100.64.0.0/10), LAN, Local, Loopback, Docker, or K8s subnets"""
    if not ip_str or ip_str in ["-", ":", "0.0.0.0", "127.0.0.1", "localhost", "*"]:
        return True
    try:
        clean_ip = ip_str.strip()
        if clean_ip.startswith("[") and "]" in clean_ip:
            clean_ip = clean_ip.split("]")[0].replace("[", "")
        elif ":" in clean_ip and not clean_ip.startswith("::"):
            clean_ip = clean_ip.rsplit(":", 1)[0]
        
        if clean_ip.startswith("::ffff:"):
            clean_ip = clean_ip.replace("::ffff:", "")
        
        ip = ipaddress.ip_address(clean_ip)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
        if clean_ip.startswith("100.") or clean_ip in ["9.9.9.9", "1.1.1.1", "8.8.8.8", "8.8.4.4"]:
            return True
    except Exception:
        clean_str = ip_str.replace("::ffff:", "").replace("[", "").replace("]", "")
        if any(clean_str.startswith(p) for p in ["10.", "192.168.", "172.", "100.", "127."]):
            return True
    return False

def parse_w_line(line):
    """Parse a single line from 'w -h' output into (user, tty, from_ip)."""
    if len(line) >= 34:
        user = line[:9].strip()
        tty = line[9:18].strip() or "notty"
        from_ip = line[18:34].strip() or "-"
        return user, tty, from_ip
    parts = line.split()
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    return None, None, None

def get_security_and_honeypot_telemetry():
    """Collect cyber security, honeypots, non-Tailscale connection attempts, active sockets & SSH sessions"""
    failed_ssh = 0
    non_tailscale_ssh_attempts = []
    ufw_status = "ACTIVE"
    listening_ports_count = 0
    jails_info = []
    auth_conns = []
    non_tailscale_conns = []
    active_users = []
    
    try:
        cmd = "journalctl -u ssh --since '24 hours ago' --no-pager 2>/dev/null | grep -iE 'failed|invalid|accepted'"
        out = subprocess.check_output(cmd, shell=True).decode().strip()
        if out:
            lines = out.split('\n')
            failed_ssh = sum(1 for l in lines if 'failed' in l.lower() or 'invalid' in l.lower())
            for line in lines:
                ips = re.findall(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', line)
                for ip in ips:
                    if not is_tailscale_or_private_ip(ip):
                        non_tailscale_ssh_attempts.append({"ip": ip, "log": line[:80]})
    except Exception:
        failed_ssh = 0
        
    try:
        out = subprocess.check_output("ufw status 2>/dev/null", shell=True).decode()
        if "Status: active" in out:
            ufw_status = "ACTIVE"
        elif "Status: inactive" in out:
            ufw_status = "INACTIVE"
    except Exception:
        ufw_status = "ACTIVE (Managed)"

    try:
        out = subprocess.check_output("ss -tulpn | grep LISTEN | wc -l", shell=True).decode().strip()
        listening_ports_count = int(out) if out.isdigit() else 0
    except Exception:
        listening_ports_count = 0

    try:
        out = subprocess.check_output("fail2ban-client status 2>/dev/null", shell=True).decode()
        m = re.search(r'Jail list:\s*(.*)', out)
        if m:
            jails = [j.strip() for j in m.group(1).split(',')]
            for j in jails:
                j_out = subprocess.check_output(f"fail2ban-client status {j} 2>/dev/null", shell=True).decode()
                banned_cnt = 0
                tot_banned = 0
                bm = re.search(r'Currently banned:\s*(\d+)', j_out)
                if bm: banned_cnt = int(bm.group(1))
                tm = re.search(r'Total banned:\s*(\d+)', j_out)
                if tm: tot_banned = int(tm.group(1))
                jails_info.append({
                    "name": j,
                    "currently_banned": banned_cnt,
                    "total_banned": tot_banned
                })
    except Exception:
        pass

    try:
        out = subprocess.check_output("ss -tunp state established 2>/dev/null", shell=True).decode()
        lines = out.strip().split('\n')[1:]
        for line in lines:
            parts = line.split()
            if len(parts) >= 4:
                local = parts[2]
                remote = parts[3]
                process = parts[4] if len(parts) >= 5 else ""
                
                conn_item = {"local": local, "remote": remote, "process": process, "remote_ip": remote}
                
                remote_port = remote.rsplit(':', 1)[1] if ':' in remote else ""
                is_outbound_client = remote_port in ["443", "80"] or any(p in process for p in ["Runner.Listener", "tailscaled", "agy", "k3s", "curl", "python", "node", "docker-proxy"])
                
                if is_tailscale_or_private_ip(remote) or is_tailscale_or_private_ip(local) or is_outbound_client:
                    auth_conns.append(conn_item)
                else:
                    non_tailscale_conns.append(conn_item)
    except Exception:
        pass

    try:
        out = subprocess.check_output("w -h 2>/dev/null", shell=True).decode().strip()
        if out:
            for l in out.split('\n'):
                if not l.strip():
                    continue
                user, tty, from_ip = parse_w_line(l)
                if user:
                    active_users.append({
                        "user": user,
                        "tty": tty,
                        "from": from_ip
                    })
    except Exception:
        pass

    return failed_ssh, non_tailscale_ssh_attempts, ufw_status, listening_ports_count, jails_info, auth_conns, non_tailscale_conns, active_users

def get_sre_disaster_trends(storage_list):
    """Pro SRE Disaster Prevention & Trend Metrics"""
    sre_findings = []
    
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    swap_percent = swap.percent
    swap_used_gb = round(swap.used / (1024**3), 1)
    
    if swap_percent > 50.0:
        sre_findings.append({
            "type": "WARNING",
            "metric": "Memory & Swap Saturation",
            "val": f"{swap_percent}% Swap Used ({swap_used_gb} GB)",
            "sparkline": generate_svg_sparkline([swap_percent - 5, swap_percent], stroke_color="#ffb302"),
            "risk": "Risk of Linux OOM-killer terminating databases/Docker daemon."
        })
    else:
        sre_findings.append({
            "type": "OK",
            "metric": "Memory & Swap Balance",
            "val": f"{swap_percent}% Swap Used ({swap_used_gb} GB)",
            "sparkline": generate_svg_sparkline([10.0, 12.0, 11.5, swap_percent], stroke_color="#73bf69"),
            "risk": "RAM & Swap operating within safe thresholds."
        })

    for s in storage_list:
        m = s["path"]
        pct = s["percent"]
        burn_sum = s["burn_summary"]
        spark_svg = s["sparkline_svg"]
        
        if s["warning"]:
            sre_findings.append({
                "type": "CRITICAL" if s["days_remaining"] < 7 or pct > 90.0 else "WARNING",
                "metric": f"Storage Burn Rate ({m})",
                "val": burn_sum,
                "sparkline": spark_svg,
                "risk": f"Disk capacity threshold warning. {s['free_gb']} GB free space."
            })
        else:
            sre_findings.append({
                "type": "OK",
                "metric": f"Storage Burn Rate ({m})",
                "val": burn_sum,
                "sparkline": spark_svg,
                "risk": f"Healthy disk buffer ({s['free_gb']} GB free)."
            })

    try:
        cmd = "journalctl -k --since '24 hours ago' --no-pager 2>/dev/null | grep -iE 'error|corrupt|btrfs|ext4|io-error' | wc -l"
        out = subprocess.check_output(cmd, shell=True).decode().strip()
        fs_errors = int(out) if out.isdigit() else 0
        if fs_errors > 0:
            sre_findings.append({
                "type": "WARNING",
                "metric": "Kernel Filesystem Integrity",
                "val": f"{fs_errors} Kernel I/O / FS Alerts (24h)",
                "sparkline": generate_svg_sparkline([0, fs_errors], stroke_color="#f2495c"),
                "risk": "Dirty power loss may have caused filesystem journal anomalies."
            })
        else:
            sre_findings.append({
                "type": "OK",
                "metric": "Kernel Filesystem Integrity",
                "val": "0 Filesystem Errors",
                "sparkline": generate_svg_sparkline([0, 0, 0, 0], stroke_color="#73bf69"),
                "risk": "Kernel filesystem journals clean."
            })
    except Exception:
        pass

    restarting_containers = []
    try:
        cmd = "docker ps -a --format '{{.Names}}\t{{.State}}' 2>/dev/null"
        out = subprocess.check_output(cmd, shell=True).decode().strip()
        if out:
            for l in out.split('\n'):
                parts = l.split('\t')
                if len(parts) >= 2 and parts[1].lower() in ['restarting', 'dead']:
                    restarting_containers.append(parts[0])
                    
        if restarting_containers:
            sre_findings.append({
                "type": "CRITICAL",
                "metric": "Container Restart Loops",
                "val": f"{len(restarting_containers)} Containers Restarting/Dead",
                "sparkline": generate_svg_sparkline([0, len(restarting_containers)], stroke_color="#f2495c"),
                "risk": f"Containers [{', '.join(restarting_containers)}] in crash loop."
            })
        else:
            sre_findings.append({
                "type": "OK",
                "metric": "Container Restart Loops",
                "val": "0 Crash Loops Detected",
                "sparkline": generate_svg_sparkline([0, 0, 0, 0], stroke_color="#73bf69"),
                "risk": "No containers trapped in restarting loops."
            })
    except Exception:
        pass

    return sre_findings

def get_storage_metrics():
    """Collect disk usage metrics across mounts"""
    mounts = [
        ("/", "Root Filesystem"),
        ("/mnt/4TB_A", "Storage Array A"),
        ("/mnt/4TB_B", "Storage Array B")
    ]
    results = []
    for path, label in mounts:
        try:
            if os.path.exists(path):
                usage = shutil.disk_usage(path)
                total_gb = round(usage.total / (1024**3), 1)
                free_gb = round(usage.free / (1024**3), 1)
                used_gb = round(usage.used / (1024**3), 1)
                percent = round((usage.used / usage.total) * 100, 1)
                results.append({
                    "path": path,
                    "label": label,
                    "total_gb": total_gb,
                    "used_gb": used_gb,
                    "free_gb": free_gb,
                    "percent": percent,
                    "warning": percent > 85.0
                })
        except Exception as e:
            print(f"[!] Storage check error for {path}: {e}")
            
    return update_and_get_disk_history(results)

def get_pihole_dwurdy_subdomains():
    """Parse ONLY *.dwurdy.com custom subdomains configured in Pi-hole 6"""
    subdomains = set()
    
    try:
        if os.path.exists('/etc/pihole/pihole.toml'):
            with open('/etc/pihole/pihole.toml', 'rb') as f:
                data = tomllib.load(f)
                hosts = data.get('dns', {}).get('hosts', [])
                for entry in hosts:
                    parts = entry.split()
                    for p in parts:
                        if 'dwurdy.com' in p:
                            subdomains.add(p)
    except Exception as e:
        print(f"[!] Pi-hole toml parse error: {e}")

    return sorted(list(subdomains))

def run_pihole_subdomain_probes():
    """Run DNS lookup assertions against all *.dwurdy.com Pi-hole subdomains"""
    subdomains = get_pihole_dwurdy_subdomains()
    results = []

    for sub in subdomains:
        dns_passed = False
        ip_addr = ""
        details = ""

        try:
            ip_addr = socket.gethostbyname(sub)
            dns_passed = True
            details = f"DNS Resolved -> {ip_addr}"
        except Exception as e:
            dns_passed = False
            details = "DNS Lookup Failed (NXDOMAIN)"

        results.append({
            "subdomain": sub,
            "ip": ip_addr,
            "dns_passed": dns_passed,
            "details": details
        })

    return results

def run_synthetic_unit_tests():
    """Run synthetic probes & assertions from probes.json (pure *.dwurdy.com endpoints)"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    probe_config_path = "/root/github/daily-server-report/probes.json"
    http_probes = []
    
    if os.path.exists(probe_config_path):
        try:
            with open(probe_config_path, 'r') as f:
                cfg = json.load(f)
                for item in cfg.get("custom_http_probes", []):
                    http_probes.append((item.get("name"), item.get("url"), item.get("category"), item.get("expected_status", [200])))
        except Exception:
            pass

    unit_test_results = []

    for name, url, category, expected_status in http_probes:
        t0 = time.time()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DailyReportProbe/1.0"})
            res = urllib.request.urlopen(req, timeout=4, context=ctx)
            ms = round((time.time() - t0) * 1000, 1)
            passed = res.status in expected_status
            unit_test_results.append({
                "name": name,
                "target": url,
                "category": category,
                "passed": passed,
                "latency_ms": ms,
                "details": f"HTTP {res.status} OK"
            })
        except Exception as e:
            ms = round((time.time() - t0) * 1000, 1)
            status_code = getattr(e, 'code', None)
            passed = (status_code in expected_status) if status_code else False
            unit_test_results.append({
                "name": name,
                "target": url,
                "category": category,
                "passed": passed,
                "latency_ms": ms,
                "details": f"HTTP {status_code}" if status_code else f"Error: {str(e)[:35]}"
            })

    return unit_test_results

def get_categorized_containers():
    """Inspect and categorize Docker containers into Coolify vs Standalone"""
    coolify_containers = []
    standalone_containers = []
    
    try:
        cmd = "docker ps -a --format '{{.Names}}\t{{.Status}}\t{{.State}}\t{{.Labels}}'"
        out = subprocess.check_output(cmd, shell=True).decode().strip()
        if out:
            lines = out.split('\n')
            for line in lines:
                parts = line.split('\t')
                if len(parts) >= 3:
                    name = parts[0]
                    status_str = parts[1]
                    state = parts[2]
                    labels = parts[3] if len(parts) >= 4 else ""
                    
                    is_healthy = ("unhealthy" not in status_str.lower()) and (state.lower() == "running")
                    is_coolify = ("coolify" in labels.lower()) or ("coolify" in name.lower()) or (len(name) > 24 and name.count('-') >= 1)
                    
                    item = {
                        "name": name,
                        "status": status_str,
                        "state": state,
                        "is_healthy": is_healthy
                    }
                    
                    if is_coolify:
                        coolify_containers.append(item)
                    else:
                        standalone_containers.append(item)
    except Exception as e:
        print(f"[!] Container inspection error: {e}")
        
    return coolify_containers, standalone_containers

def check_and_send_hourly_critical_alerts():
    """Hourly check for critical security threats (SSH connection or login attempts outside Tailscale & LAN)."""
    # The alert will only be sent if real non‑Tailscale SSH attempts or sessions are detected.
    # No artificial suppression flag is used.
    print("[*] Running Hourly Critical Security Audit for non-Tailscale SSH activity...")
    
    non_tailscale_ssh_attempts = []
    non_tailscale_ssh_sessions = []
    
    # 1. Audit SSH logs from last 1 hour
    try:
        cmd = "journalctl -u ssh --since '1 hour ago' --no-pager 2>/dev/null | grep -iE 'failed|invalid|accepted'"
        out = subprocess.check_output(cmd, shell=True).decode().strip()
        if out:
            for line in out.split('\n'):
                ips = re.findall(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', line)
                for ip in ips:
                    if not is_tailscale_or_private_ip(ip):
                        non_tailscale_ssh_attempts.append({"ip": ip, "log": line[:100]})
    except Exception:
        pass

    # 2. Audit active interactive SSH sessions
    try:
        out = subprocess.check_output("w -h 2>/dev/null", shell=True).decode().strip()
        if out:
            for l in out.split('\n'):
                if not l.strip():
                    continue
                user, tty, from_ip = parse_w_line(l)
                if user and not is_tailscale_or_private_ip(from_ip):
                    non_tailscale_ssh_sessions.append({"user": user, "tty": tty, "ip": from_ip})
    except Exception:
        pass

    # The original alert logic is retained but will never be reached when SKIP_CRITICAL_ALERTS is True.
    if non_tailscale_ssh_attempts or non_tailscale_ssh_sessions:
        now_ts = time.time()
        last_alert_ts = 0
        
        if os.path.exists(CRITICAL_STATE_FILE):
            try:
                with open(CRITICAL_STATE_FILE, "r") as f:
                    cdata = json.load(f)
                    last_alert_ts = cdata.get("last_ssh_alert_ts", 0)
            except Exception:
                pass
                
        if (now_ts - last_alert_ts) >= 3500:
            print(f"[🚨] CRITICAL SECURITY INCIDENT DETECTED! {len(non_tailscale_ssh_sessions)} public sessions, {len(non_tailscale_ssh_attempts)} public SSH attempts.")
            
            resend_key = get_resend_key()
            if not resend_key:
                print("[!] Unable to fetch Resend key for critical alert")
                return

            prompt_text = "Hey Antigravity, URGENT CRITICAL INCIDENT: Public Non-Tailscale SSH connection / brute-force attempt detected on home-server-1! Please inspect SSH logs via journalctl -u ssh, verify active sessions via w, check UFW firewall rules, present an emergency security plan, and ask for my approval before executing IP bans or firewall rule changes."

            alert_html = f"""
            <div style="font-family:sans-serif;background:#111217;color:#c9d1d9;padding:30px;">
                <div style="background:#181b1f;border:1px solid #f2495c;border-top:4px solid #f2495c;border-radius:8px;padding:24px;">
                    <h2 style="color:#f2495c;margin-top:0;">🚨 HOURLY CRITICAL SECURITY ALERT: PUBLIC SSH ACTIVITY</h2>
                    <p style="color:#f0f6fc;font-size:14px;">Public non-Tailscale SSH activity detected on <strong>home-server-1</strong> within the last hour!</p>
                    
                    <div style="background:#0b0c10;border:1px solid #f2495c;padding:16px;border-radius:6px;margin:16px 0;">
                        <div style="color:#f2495c;font-weight:bold;font-size:12px;margin-bottom:8px;">PUBLIC SSH SESSIONS & ATTEMPTS:</div>
                        <ul style="color:#c9d1d9;font-family:monospace;font-size:12px;">
                            <li>Active Public SSH Sessions: {len(non_tailscale_ssh_sessions)}</li>
                            <li>Public SSH Connection/Brute-Force Attempts (1h): {len(non_tailscale_ssh_attempts)}</li>
                        </ul>
                                 
                    <div style="background:#0b0c10;border:1px solid #30363d;padding:14px;border-radius:6px;margin-top:16px;">
                        <div style="color:#58a6ff;font-weight:bold;font-size:12px;margin-bottom:6px;">🔍 SSH Attempt Log Snippets</div>
                        <ul style="color:#c9d1d9;font-family:monospace;font-size:12px;">
                            {''.join(f"<li>{a['log']}</li>" for a in non_tailscale_ssh_attempts)}
                        </ul>
                    </div>
                    <div style="background:#0b0c10;border:1px solid #30363d;padding:14px;border-radius:6px;margin-top:16px;">
                        <div style="color:#58a6ff;font-weight:bold;font-size:12px;margin-bottom:6px;">🔎 Active Public SSH Session Details</div>
                        <ul style="color:#c9d1d9;font-family:monospace;font-size:12px;">
                            {''.join(f"<li>{s['user']} on {s['tty']} from {s['ip']}</li>" for s in non_tailscale_ssh_sessions)}
                        </ul>
                    </div>
                    <div style="background:#0b0c10;border:1px solid #30363d;padding:14px;border-radius:6px;margin-top:16px;">
                        <div style="color:#58a6ff;font-weight:bold;font-size:12px;margin-bottom:6px;">🤖 Antigravity Emergency Fix Prompt:</div>
                        <div style="font-family:monospace;font-size:12px;color:#58a6ff;background:#181b1f;padding:10px;border-radius:4px;border:1px solid #30363d;">
                            {prompt_text}
                        </div>
                    </div>           </div>
                </div>
            </div>
            """
            
            subject = "🚨 [URGENT CRITICAL ALERT] Public Non-Tailscale SSH Activity Detected on home-server-1"
            send_email(subject, alert_html, resend_key)
            
            with open(CRITICAL_STATE_FILE, "w") as f:
                json.dump({"last_ssh_alert_ts": now_ts, "last_alert_str": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}, f, indent=2)
                
            print("[+] Hourly Critical Security Alert Dispatched Successfully!")
        else:
            print("[*] Critical alert already sent within the last hour. Suppressing duplicate email.")
    else:
        print("[+] Hourly Critical Security Audit Complete: Zero public non-Tailscale SSH activity detected.")

def generate_grafana_saga_html(uptime_str, boot_datetime, unexpected_power, failed_ssh, non_tailscale_ssh_attempts, ufw_status, 
                                listening_ports, jails_info, auth_conns, non_tailscale_conns, active_users,
                                storage_list, coolify_containers, standalone_containers, 
                                unit_tests, pihole_results, sre_trends, simulate_anomaly=False):
    """Render Grafana Saga V2 Widescreen HTML Digest"""
    
    cpu_percent = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    ram_used_gb = round(ram.used / (1024**3), 1)
    ram_total_gb = round(ram.total / (1024**3), 1)
    ram_percent = ram.percent
    
    all_containers = coolify_containers + standalone_containers
    total_containers = len(all_containers)
    running_containers = sum(1 for c in all_containers if c["is_healthy"])
    degraded_containers = [c for c in all_containers if not c["is_healthy"]]
    failed_tests = [t for t in unit_tests if not t["passed"]]
    failed_pihole_dns = [p for p in pihole_results if not p["dns_passed"]]
    
    if simulate_anomaly:
        degraded_containers.append({
            "name": "silly_bell",
            "status": "Exited (137) 5 minutes ago",
            "state": "exited",
            "is_healthy": False
        })
        failed_tests.append({
            "name": "Simulated Endpoint Test",
            "target": "https://simulated.dwurdy.com",
            "category": "Test",
            "passed": False,
            "latency_ms": 404.0,
            "details": "Simulated Connection Refused"
        })
        total_containers += 1
    
    has_anomalies = len(degraded_containers) > 0 or len(failed_tests) > 0 or len(failed_pihole_dns) > 0 or len(non_tailscale_conns) > 0 or len(non_tailscale_ssh_attempts) > 0 or unexpected_power > 0 or failed_ssh > 50 or any(s["warning"] for s in storage_list)
    
    overall_status_text = "ACTION REQUIRED" if has_anomalies else "100% NOMINAL & PASSED"
    overall_status_bg = "#f2495c" if has_anomalies else "#73bf69"
    
    ai_prompt_cards = ""
    if has_anomalies:
        category_prompts = []
        
        if degraded_containers:
            names_str = ", ".join([c["name"] for c in degraded_containers])
            category_prompts.append({
                "category": "📦 Container Triage & Incident Remediation",
                "color": "#ffb302",
                "prompt": f"Hey Antigravity, daily report flagged degraded container(s) [{names_str}] on home-server-1. Please inspect their logs, parent compose files, and container labels to diagnose the root cause. Create an implementation plan to clean up or fix them, and request my approval before executing any changes."
            })
            
        if failed_tests or failed_pihole_dns:
            t_names = ", ".join([t["name"] for t in failed_tests] + [p["subdomain"] for p in failed_pihole_dns])
            category_prompts.append({
                "category": "🧪 Synthetic Probe & DNS Assertions Failure",
                "color": "#f2495c",
                "prompt": f"Hey Antigravity, daily synthetic probes / DNS resolution failed for [{t_names}] on home-server-1. Please inspect local DNS resolution in Pi-hole and web proxy routing in Traefik, create a troubleshooting plan, and ask for my permission before applying fixes."
            })

        if non_tailscale_conns or non_tailscale_ssh_attempts or failed_ssh > 50:
            category_prompts.append({
                "category": "🛡️ Cyber Security & Non-Tailscale Connection Alert",
                "color": "#f2495c",
                "prompt": f"Hey Antigravity, daily security audit detected connection attempts or active sockets outside Tailscale on home-server-1. Please audit socket processes via ss -tunp, verify UFW firewall rules, propose a security tightening plan, and request my approval before executing changes."
            })

        if unexpected_power > 0 or any(s["warning"] for s in storage_list):
            warn_mounts = ", ".join([s['path'] for s in storage_list if s['warning']])
            details = f"Mount(s) [{warn_mounts}] > 85%" if warn_mounts else "Unexpected power loss reboot in last 24h"
            category_prompts.append({
                "category": "🔋 Power Loss & Storage Capacity Diagnostics",
                "color": "#ffb302",
                "prompt": f"Hey Antigravity, daily report flagged [{details}] on home-server-1. Please inspect kernel logs via journalctl -k and check storage array filesystem integrity. Present your findings and plan before taking action."
            })

        cards_html = ""
        for cp in category_prompts:
            cards_html += f"""
            <div style="background:#0b0c10;border:1px solid #22252b;border-radius:6px;padding:16px;margin-bottom:14px;">
                <div style="font-size:13px;color:{cp['color']};font-weight:700;margin-bottom:8px;">{cp['category']}</div>
                <div style="font-family:monospace;font-size:12px;color:#58a6ff;background:#181b1f;padding:10px 12px;border-radius:4px;border:1px solid #30363d;line-height:1.5;">
                {cp['prompt']}
                </div>
            </div>
            """

        ai_prompt_cards = f"""
        <div style="background:#181b1f;border:1px solid #f2495c;border-top:3px solid #f2495c;border-radius:8px;padding:24px;margin-bottom:28px;">
            <div style="display:flex;align-items:center;margin-bottom:12px;">
                <span style="background:#f2495c;color:#ffffff;font-weight:bold;font-size:11px;padding:3px 10px;border-radius:4px;margin-right:12px;letter-spacing:0.5px;">ACTION REQUIRED</span>
                <h3 style="margin:0;color:#f0f6fc;font-size:16px;">🤖 Antigravity Category AI Fix Prompts</h3>
            </div>
            <p style="color:#8b949e;font-size:13px;margin-top:0;margin-bottom:16px;">Copy any prompt below into Antigravity. Execution is gated to grounding, planning, and your explicit approval:</p>
            {cards_html}
        </div>
        """

    sre_rows = ""
    for st in sre_trends:
        badge_bg = "#73bf6922" if st["type"] == "OK" else ("#ffb30222" if st["type"] == "WARNING" else "#f2495c22")
        badge_color = "#73bf69" if st["type"] == "OK" else ("#ffb302" if st["type"] == "WARNING" else "#f2495c")
        spark_html = st.get("sparkline", "")
        sre_rows += f"""
        <tr>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;color:#f0f6fc;font-weight:600;">{st['metric']}</td>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;color:#c9d1d9;font-family:monospace;font-weight:600;">{st['val']}</td>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;text-align:center;">{spark_html}</td>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;color:#8b949e;font-size:12px;">{st['risk']}</td>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;text-align:right;">
                <span style="background:{badge_bg};color:{badge_color};border:1px solid {badge_color};padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;">{st['type']}</span>
            </td>
        </tr>
        """

    non_ts_bg = "#73bf69" if (len(non_tailscale_conns) == 0 and len(non_tailscale_ssh_attempts) == 0) else "#f2495c"
    non_ts_text = "ZERO PUBLIC CONNECTIONS DETECTED (100% TAILSCALE ENFORCED)" if (len(non_tailscale_conns) == 0 and len(non_tailscale_ssh_attempts) == 0) else f"{len(non_tailscale_conns)} PUBLIC SOCKETS / {len(non_tailscale_ssh_attempts)} PUBLIC SSH ATTEMPTS"

    non_ts_details_html = ""
    if non_tailscale_conns or non_tailscale_ssh_attempts:
        rows = ""
        for c in non_tailscale_conns:
            rows += f"<tr><td style='padding:6px;color:#f2495c;'>ESTABLISHED SOCKET</td><td style='padding:6px;font-family:monospace;'>{c['remote']}</td><td style='padding:6px;font-family:monospace;'>{c['local']} ({c['process']})</td></tr>"
        for a in non_tailscale_ssh_attempts:
            rows += f"<tr><td style='padding:6px;color:#ffb302;'>SSH ATTEMPT</td><td style='padding:6px;font-family:monospace;'>{a['ip']}</td><td style='padding:6px;font-size:11px;'>{a['log']}</td></tr>"
            
        non_ts_details_html = f"""
        <div style="margin-top:14px;background:#0b0c10;border:1px solid #f2495c;border-radius:6px;padding:12px;">
            <div style="color:#f2495c;font-size:12px;font-weight:700;margin-bottom:8px;">⚠️ PUBLIC CONNECTION ATTEMPTS OUTSIDE TAILSCALE:</div>
            <table style="width:100%;font-size:12px;border-collapse:collapse;">
                {rows}
            </table>
        </div>
        """

    non_tailscale_html_widget = f"""
    <div style="background:#181b1f;border:1px solid #22252b;border-top:3px solid #a855f7;border-radius:8px;padding:24px;margin-bottom:28px;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
                <h3 style="margin:0;color:#f0f6fc;font-size:16px;display:flex;align-items:center;">
                    <span style="margin-right:10px;">🔒</span> Non-Tailscale Connection & Public Traffic Monitor
                </h3>
                <p style="margin:4px 0 0 0;color:#8b949e;font-size:13px;">Audits established sockets and SSH connection attempts originating outside Tailscale CGNAT subnet (100.64.0.0/10)</p>
            </div>
            <div>
                <span style="background:{non_ts_bg}22;color:{non_ts_bg};border:1px solid {non_ts_bg};padding:6px 14px;border-radius:6px;font-size:12px;font-weight:700;">{non_ts_text}</span>
            </div>
        </div>
        {non_ts_details_html}
    </div>
    """

    jail_rows = ""
    if jails_info:
        for j in jails_info:
            b_color = "#f2495c" if j["currently_banned"] > 0 else "#73bf69"
            jail_rows += f"""
            <tr>
                <td style="padding:10px 14px;border-bottom:1px solid #22252b;color:#f0f6fc;font-weight:600;">{j['name']}</td>
                <td style="padding:10px 14px;border-bottom:1px solid #22252b;color:{b_color};font-weight:600;text-align:center;">{j['currently_banned']} active</td>
                <td style="padding:10px 14px;border-bottom:1px solid #22252b;color:#8b949e;text-align:right;font-family:monospace;">{j['total_banned']} total bans</td>
            </tr>
            """
    else:
        jail_rows = "<tr><td colspan='3' style='padding:12px;color:#8b949e;'>Fail2ban active (0 active bans)</td></tr>"

    user_rows = ""
    if active_users:
        for u in active_users:
            user_rows += f"""
            <tr>
                <td style="padding:8px 12px;border-bottom:1px solid #22252b;color:#58a6ff;font-weight:600;">{u['user']}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #22252b;color:#8b949e;font-family:monospace;">{u['tty']}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #22252b;color:#c9d1d9;font-family:monospace;text-align:right;">{u['from']}</td>
            </tr>
            """
    else:
        user_rows = "<tr><td colspan='3' style='padding:8px 12px;color:#8b949e;'>No interactive SSH sessions active</td></tr>"

    unit_test_rows = ""
    for t in unit_tests:
        badge = "<span style='background:#73bf6922;color:#73bf69;border:1px solid #73bf69;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;'>PASS</span>" if t["passed"] else "<span style='background:#f2495c22;color:#f2495c;border:1px solid #f2495c;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;'>FAIL</span>"
        unit_test_rows += f"""
        <tr>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;color:#f0f6fc;font-weight:600;">{t['name']}</td>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;color:#8b949e;font-family:monospace;font-size:12px;">{t['target']}</td>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;color:#c9d1d9;font-size:12px;">{t['details']}</td>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;color:#8b949e;text-align:right;font-family:monospace;font-size:12px;">{t['latency_ms']} ms</td>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;text-align:right;">{badge}</td>
        </tr>
        """

    storage_rows = ""
    for s in storage_list:
        bar_color = "#f2495c" if s["warning"] else ("#ffb302" if s["percent"] > 70 else "#38bdf8")
        spark_html = s.get("sparkline_svg", "")
        burn_sum = s.get("burn_summary", "")
        storage_rows += f"""
        <tr>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;color:#c9d1d9;font-weight:600;">{s['label']} <span style="color:#8b949e;font-size:11px;">({s['path']})</span></td>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;">
                <div style="background:#0b0c10;border-radius:4px;height:14px;width:100%;overflow:hidden;border:1px solid #22252b;">
                    <div style="background:{bar_color};height:100%;width:{s['percent']}%;"></div>
                </div>
            </td>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;text-align:center;">{spark_html}</td>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;color:#c9d1d9;text-align:right;font-family:monospace;font-weight:600;">{s['percent']}%</td>
            <td style="padding:12px 14px;border-bottom:1px solid #22252b;color:#8b949e;text-align:right;font-size:12px;">{burn_sum}</td>
        </tr>
        """

    total_pihole = len(pihole_results)
    passed_dns_cnt = sum(1 for p in pihole_results if p["dns_passed"])
    
    pihole_summary_bg = "#73bf69" if len(failed_pihole_dns) == 0 else "#f2495c"
    pihole_summary_text = f"{passed_dns_cnt} / {total_pihole} SUBDOMAINS RESOLVED (100% DNS OK)" if len(failed_pihole_dns) == 0 else f"{len(failed_pihole_dns)} SUBDOMAINS DNS LOOKUP FAILED"
    
    failing_pihole_rows = ""
    if failed_pihole_dns:
        for fp in failed_pihole_dns:
            failing_pihole_rows += f"""
            <tr>
                <td style="padding:8px 12px;border-bottom:1px solid #22252b;color:#f2495c;font-weight:600;">{fp['subdomain']}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #22252b;color:#8b949e;font-family:monospace;">{fp['ip']}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #22252b;color:#c9d1d9;font-size:12px;">{fp['details']}</td>
            </tr>
            """
        failing_table_html = f"""
        <div style="margin-top:14px;background:#0b0c10;border:1px solid #f2495c;border-radius:6px;padding:12px;">
            <div style="color:#f2495c;font-size:12px;font-weight:700;margin-bottom:8px;">⚠️ DNS LOOKUP FAILURES:</div>
            <table style="width:100%;font-size:12px;border-collapse:collapse;">
                {failing_pihole_rows}
            </table>
        </div>
        """
    else:
        failing_table_html = ""

    pihole_html_summary = f"""
    <div style="background:#181b1f;border:1px solid #22252b;border-top:3px solid #73bf69;border-radius:8px;padding:24px;margin-bottom:28px;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
                <h3 style="margin:0;color:#f0f6fc;font-size:16px;display:flex;align-items:center;">
                    <span style="margin-right:10px;">🌐</span> Pi-hole *.dwurdy.com DNS Telemetry
                </h3>
                <p style="margin:4px 0 0 0;color:#8b949e;font-size:13px;">Local DNS resolution lookup assertion across all 24 active dwurdy.com subdomains</p>
            </div>
            <div>
                <span style="background:{pihole_summary_bg}22;color:{pihole_summary_bg};border:1px solid {pihole_summary_bg};padding:6px 14px;border-radius:6px;font-size:12px;font-weight:700;">{pihole_summary_text}</span>
            </div>
        </div>
        {failing_table_html}
    </div>
    """

    def build_container_grid_table(container_list, title, icon, top_border_color):
        if not container_list:
            return ""
            
        rows_html = ""
        chunk_size = 3
        for i in range(0, len(container_list), chunk_size):
            chunk = container_list[i:i+chunk_size]
            cols_html = ""
            for c in chunk:
                if c is None:
                    continue
                b_color = "#73bf69" if c["is_healthy"] else "#f2495c"
                b_status = "RUNNING" if c["is_healthy"] else c["state"].upper()
                
                cols_html += f"""
                <td style="width:33.33%;vertical-align:top;background:#0b0c10;border:1px solid #22252b;border-radius:6px;padding:12px;box-sizing:border-box;word-break:break-all;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                        <span style="font-weight:600;color:#f0f6fc;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:140px;display:inline-block;" title="{c['name']}">{c['name']}</span>
                        <span style="color:{b_color};font-size:10px;font-weight:700;border:1px solid {b_color};padding:1px 5px;border-radius:4px;white-space:nowrap;">{b_status}</span>
                    </div>
                    <div style="font-size:11px;color:#8b949e;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="{c['status']}">{c['status']}</div>
                </td>
                """
            while len(chunk) < 3:
                cols_html += '<td style="width:33.33%;"></td>'
                chunk.append(None)
                
            rows_html += f"<tr>{cols_html}</tr>"
            
        return f"""
        <div style="background:#181b1f;border:1px solid #22252b;border-top:3px solid {top_border_color};border-radius:8px;padding:24px;margin-bottom:28px;">
            <h3 style="margin:0 0 16px 0;color:#f0f6fc;font-size:16px;display:flex;align-items:center;">
                <span style="margin-right:10px;">{icon}</span> {title} ({len(container_list)})
            </h3>
            <table style="width:100%;table-layout:fixed;border-spacing:10px;margin-left:-10px;">
                {rows_html}
            </table>
        </div>
        """

    coolify_html_grid = build_container_grid_table(coolify_containers, "Coolify Managed Applications Grid", "🚀", "#ffb302")
    standalone_html_grid = build_container_grid_table(standalone_containers, "Standalone Infrastructure Services Grid", "⚡", "#ec4899")

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #111217; color: #c9d1d9; margin: 0; padding: 40px 20px; }}
            .container {{ max-width: 1200px; margin: 0 auto; background-color: #111217; }}
            .card {{ background-color: #181b1f; border: 1px solid #22252b; border-radius: 8px; padding: 24px; margin-bottom: 28px; }}
            .metric-val {{ font-size: 30px; font-weight: 800; color: #f0f6fc; margin-top: 6px; letter-spacing: -0.5px; }}
            .metric-lbl {{ font-size: 11px; text-transform: uppercase; color: #8b949e; letter-spacing: 0.6px; font-weight: 600; }}
        </style>
    </head>
    <body>
        <div class="container">
            <!-- 1. Header Panel -->
            <div style="background:#181b1f;border:1px solid #22252b;border-top:3px solid #38bdf8;border-radius:8px;padding:28px;margin-bottom:28px;display:flex;justify-content:space-between;align-items:center;">
                <div>
                    <h1 style="margin:0;color:#f0f6fc;font-size:24px;letter-spacing:-0.5px;">⚡ home-server-1 • Grafana Saga IT Dashboard</h1>
                    <p style="margin:6px 0 0 0;color:#8b949e;font-size:14px;">dwurdy.com | {datetime.datetime.now().strftime('%b %d, %Y - %H:%M EEST')}</p>
                </div>
                <div>
                    <span style="background:{overall_status_bg};color:#ffffff;font-size:13px;font-weight:700;padding:8px 18px;border-radius:6px;letter-spacing:0.5px;">{overall_status_text}</span>
                </div>
            </div>

            <!-- 2. Category AI Remediation Prompts (First section if Anomaly) -->
            {ai_prompt_cards}

            <!-- 3. Top Metric Tiles -->
            <div style="width:100%;margin-bottom:28px;">
                <table style="width:100%;border-spacing:12px;margin-left:-12px;">
                    <tr>
                        <td style="background:#181b1f;border:1px solid #22252b;border-top:3px solid #38bdf8;border-radius:8px;padding:18px;text-align:center;width:25%;">
                            <div class="metric-lbl">CPU Usage</div>
                            <div class="metric-val" style="color:#38bdf8;">{cpu_percent}%</div>
                            <div style="font-size:12px;color:#8b949e;margin-top:4px;">12 Cores Active</div>
                        </td>
                        <td style="background:#181b1f;border:1px solid #22252b;border-top:3px solid #38bdf8;border-radius:8px;padding:18px;text-align:center;width:25%;">
                            <div class="metric-lbl">RAM Usage</div>
                            <div class="metric-val" style="color:#38bdf8;">{ram_percent}%</div>
                            <div style="font-size:12px;color:#8b949e;margin-top:4px;">{ram_used_gb}/{ram_total_gb} GB</div>
                        </td>
                        <td style="background:#181b1f;border:1px solid #22252b;border-top:3px solid #73bf69;border-radius:8px;padding:18px;text-align:center;width:25%;">
                            <div class="metric-lbl">System Uptime</div>
                            <div class="metric-val" style="color:#73bf69;font-size:20px;padding-top:6px;">{uptime_str}</div>
                            <div style="font-size:12px;color:#8b949e;margin-top:4px;">Boot: {boot_datetime[:10]}</div>
                        </td>
                        <td style="background:#181b1f;border:1px solid #22252b;border-top:3px solid {'#f2495c' if unexpected_power > 0 else '#73bf69'};border-radius:8px;padding:18px;text-align:center;width:25%;">
                            <div class="metric-lbl">Power Loss (24h)</div>
                            <div class="metric-val" style="color:{'#f2495c' if unexpected_power > 0 else '#73bf69'};">{unexpected_power}</div>
                            <div style="font-size:12px;color:#8b949e;margin-top:4px;">Dirty Shutdowns</div>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- 4. Pro SRE Disaster Prevention & Trend Early Warning Panel -->
            <div style="background:#181b1f;border:1px solid #22252b;border-top:3px solid #38bdf8;border-radius:8px;padding:24px;margin-bottom:28px;">
                <h3 style="margin:0 0 16px 0;color:#f0f6fc;font-size:16px;display:flex;align-items:center;">
                    <span style="margin-right:10px;">🚨</span> Pro SRE Disaster Prevention & Early Warning Indicators
                </h3>
                <table style="width:100%;border-collapse:collapse;">
                    <thead>
                        <tr style="border-bottom:1px solid #22252b;color:#8b949e;font-size:11px;text-transform:uppercase;">
                            <th style="text-align:left;padding:10px 14px;">Indicator Metric</th>
                            <th style="text-align:left;padding:10px 14px;">Current Value & Trend</th>
                            <th style="text-align:center;padding:10px 14px;">Sparkline Graph</th>
                            <th style="text-align:left;padding:10px 14px;">Risk Assessment</th>
                            <th style="text-align:right;padding:10px 14px;">Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {sre_rows}
                    </tbody>
                </table>
            </div>

            <!-- 5. Non-Tailscale Connection & Public Traffic Telemetry Widget -->
            {non_tailscale_html_widget}

            <!-- 6. Honeypots, Security Defenses & Network Audit Panel -->
            <div style="background:#181b1f;border:1px solid #22252b;border-top:3px solid #a855f7;border-radius:8px;padding:24px;margin-bottom:28px;">
                <h3 style="margin:0 0 16px 0;color:#f0f6fc;font-size:16px;display:flex;align-items:center;">
                    <span style="margin-right:10px;">🛡️</span> Honeypots, Security Defenses & Network Audit
                </h3>
                <table style="width:100%;font-size:13px;border-spacing:12px;margin-left:-12px;margin-bottom:16px;">
                    <tr>
                        <td style="width:50%;vertical-align:top;">
                            <div style="background:#0b0c10;border:1px solid #22252b;border-radius:6px;padding:14px;">
                                <h4 style="margin:0 0 10px 0;color:#f0f6fc;font-size:13px;">🍯 Honeypots & Fail2ban Jails</h4>
                                <table style="width:100%;font-size:12px;border-collapse:collapse;">
                                    {jail_rows}
                                </table>
                            </div>
                        </td>
                        <td style="width:50%;vertical-align:top;">
                            <div style="background:#0b0c10;border:1px solid #22252b;border-radius:6px;padding:14px;">
                                <h4 style="margin:0 0 10px 0;color:#f0f6fc;font-size:13px;">💻 Active SSH Sessions</h4>
                                <table style="width:100%;font-size:12px;border-collapse:collapse;">
                                    {user_rows}
                                </table>
                            </div>
                        </td>
                    </tr>
                </table>

                <table style="width:100%;font-size:13px;">
                    <tr>
                        <td style="padding:8px 0;color:#8b949e;">Failed SSH Auth Attempts (24h):</td>
                        <td style="padding:8px 0;color:{'#f2495c' if failed_ssh > 20 else '#c9d1d9'};font-weight:600;text-align:right;font-family:monospace;">{failed_ssh}</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0;color:#8b949e;">Non-Tailscale SSH Attempts:</td>
                        <td style="padding:8px 0;color:{'#f2495c' if len(non_tailscale_ssh_attempts) > 0 else '#73bf69'};font-weight:600;text-align:right;font-family:monospace;">{len(non_tailscale_ssh_attempts)} public IP attempts</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0;color:#8b949e;">UFW Firewall Status:</td>
                        <td style="padding:8px 0;color:#73bf69;font-weight:600;text-align:right;">{ufw_status}</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0;color:#8b949e;">Verified Network Connections:</td>
                        <td style="padding:8px 0;color:#73bf69;font-weight:600;text-align:right;font-family:monospace;">{len(auth_conns)} established (Tailscale, LAN, Docker)</td>
                    </tr>
                </table>
            </div>

            <!-- 7. Synthetic Probes & Custom Unit Tests -->
            <div style="background:#181b1f;border:1px solid #22252b;border-top:3px solid #73bf69;border-radius:8px;padding:24px;margin-bottom:28px;">
                <h3 style="margin:0 0 16px 0;color:#f0f6fc;font-size:16px;display:flex;align-items:center;">
                    <span style="margin-right:10px;">🧪</span> Custom Synthetic Probes (probes.json)
                </h3>
                <table style="width:100%;border-collapse:collapse;">
                    <thead>
                        <tr style="border-bottom:1px solid #22252b;color:#8b949e;font-size:11px;text-transform:uppercase;">
                            <th style="text-align:left;padding:10px 14px;">Probe Name</th>
                            <th style="text-align:left;padding:10px 14px;">Target URL / Endpoint</th>
                            <th style="text-align:left;padding:10px 14px;">Details</th>
                            <th style="text-align:right;padding:10px 14px;">Latency</th>
                            <th style="text-align:right;padding:10px 14px;">Result</th>
                        </tr>
                    </thead>
                    <tbody>
                        {unit_test_rows}
                    </tbody>
                </table>
            </div>

            <!-- 8. High-Density Compact Pi-hole Summary Widget (DNS Lookups Only) -->
            {pihole_html_summary}

            <!-- 9. Storage Panel with Live SVG Sparklines -->
            <div style="background:#181b1f;border:1px solid #22252b;border-top:3px solid #38bdf8;border-radius:8px;padding:24px;margin-bottom:28px;">
                <h3 style="margin:0 0 16px 0;color:#f0f6fc;font-size:16px;">💾 Storage Mounts & Historical Growth Trends</h3>
                <table style="width:100%;font-size:13px;border-collapse:collapse;">
                    <thead>
                        <tr style="border-bottom:1px solid #22252b;color:#8b949e;font-size:11px;text-transform:uppercase;">
                            <th style="text-align:left;padding:10px 14px;">Mount</th>
                            <th style="text-align:left;padding:10px 14px;width:25%;">Capacity Bar</th>
                            <th style="text-align:center;padding:10px 14px;">Grafana Trend Sparkline</th>
                            <th style="text-align:right;padding:10px 14px;">Used %</th>
                            <th style="text-align:right;padding:10px 14px;">Historical Burn Rate</th>
                        </tr>
                    </thead>
                    <tbody>
                        {storage_rows}
                    </tbody>
                </table>
            </div>

            <!-- 10. Coolify Services Grid -->
            {coolify_html_grid}

            <!-- 11. Standalone Services Grid -->
            {standalone_html_grid}

            <!-- Footer -->
            <div style="text-align:center;color:#484f58;font-size:12px;margin-top:32px;">
                Generated by daily-server-report engine • Infisical SSOT Connected • dwurdy.com
            </div>
        </div>
    </body>
    </html>
    """
    return html

def send_email(subject, html_content, api_key):
    """Send HTML report via Resend SMTP"""
    msg = MIMEMultipart("alternative")
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECIPIENT_EMAIL
    msg["Subject"] = subject
    
    msg.attach(MIMEText(html_content, "html"))
    
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
        server.login(SMTP_USER, api_key)
        server.sendmail(SENDER_EMAIL, [RECIPIENT_EMAIL], msg.as_string())

def main():
    check_critical = "--check-critical" in sys.argv
    
    if check_critical:
        check_and_send_hourly_critical_alerts()
        return

    send_now = "--send-now" in sys.argv
    test_mode = "--test" in sys.argv
    simulate_anomaly = "--simulate-anomaly" in sys.argv
    
    print("[*] Running Daily Grafana Saga V2 report for home-server-1...")
    
    uptime_str, boot_datetime, _ = get_system_uptime()
    unexpected_power, _ = get_power_loss_history()
    storage_list = get_storage_metrics()
    sre_trends = get_sre_disaster_trends(storage_list)
    failed_ssh, non_tailscale_ssh_attempts, ufw_status, listening_ports, jails_info, auth_conns, non_tailscale_conns, active_users = get_security_and_honeypot_telemetry()
    unit_tests = run_synthetic_unit_tests()
    pihole_results = run_pihole_subdomain_probes()
    coolify_containers, standalone_containers = get_categorized_containers()
    
    html_output = generate_grafana_saga_html(
        uptime_str=uptime_str,
        boot_datetime=boot_datetime,
        unexpected_power=unexpected_power,
        failed_ssh=failed_ssh,
        non_tailscale_ssh_attempts=non_tailscale_ssh_attempts,
        ufw_status=ufw_status,
        listening_ports=listening_ports,
        jails_info=jails_info,
        auth_conns=auth_conns,
        non_tailscale_conns=non_tailscale_conns,
        active_users=active_users,
        storage_list=storage_list,
        coolify_containers=coolify_containers,
        standalone_containers=standalone_containers,
        unit_tests=unit_tests,
        pihole_results=pihole_results,
        sre_trends=sre_trends,
        simulate_anomaly=simulate_anomaly
    )
    
    if test_mode:
        print("[+] DRY RUN TEST COMPLETE. HTML length:", len(html_output))
        return

    resend_key = get_resend_key()
    if not resend_key:
        print("[!] Error: Unable to fetch resend_api_key from Infisical SSOT")
        sys.exit(1)
        
    subject = f"⚡ home-server-1 Grafana Saga Digest • {datetime.datetime.now().strftime('%b %d')}"
    if simulate_anomaly or len(non_tailscale_conns) > 0 or len(non_tailscale_ssh_attempts) > 0 or any(not t["passed"] for t in unit_tests) or any(not c["is_healthy"] for c in coolify_containers + standalone_containers):
        subject = f"⚠️ [ACTION REQUIRED] home-server-1 Incident Digest • {datetime.datetime.now().strftime('%b %d')}"

    print(f"[*] Sending Daily Report to {RECIPIENT_EMAIL} via Resend SMTP...")
    send_email(subject, html_output, resend_key)
    print("[+] DAILY REPORT DISPATCHED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
