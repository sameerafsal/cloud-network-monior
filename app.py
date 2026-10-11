import os
import re
import time
import socket
import sqlite3
import platform
import subprocess
import urllib.request
import json
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import psutil
except ImportError:
    psutil = None

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "cloud-network-monitor-secret-key-2026")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "database.db")

# Global tracking for bandwidth delta calculations
_last_io_counters = None
_last_io_time = None
_traffic_history = []  # Rolling in-memory window for Chart.js (last 15 points)


def get_db():
    """Returns a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates database tables and populates initial demo data if empty."""
    conn = get_db()
    cursor = conn.cursor()

    # Table: users
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'Admin',
            created_at TEXT NOT NULL
        )
    """)

    # Table: devices
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            latency_ms REAL DEFAULT 0,
            packet_loss REAL DEFAULT 0,
            last_checked TEXT NOT NULL
        )
    """)

    # Table: network_logs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT NOT NULL,
            latency_ms REAL DEFAULT 0,
            packet_loss REAL DEFAULT 0,
            timestamp TEXT NOT NULL
        )
    """)

    # Table: alerts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            severity TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            is_resolved INTEGER DEFAULT 0
        )
    """)

    conn.commit()

    # Seed Admin User if not exists
    cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if not cursor.fetchone():
        hashed_password = generate_password_hash("admin123")
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            ("admin", hashed_password, "Network Admin", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()

    # Seed Demo Devices if table is empty
    cursor.execute("SELECT COUNT(*) as cnt FROM devices")
    if cursor.fetchone()["cnt"] == 0:
        demo_devices = [
            ("Router (Default Gateway)", "192.168.1.1", "Online", 1.8, 0.0),
            ("Google Public DNS", "8.8.8.8", "Online", 14.5, 0.0),
            ("Cloudflare DNS", "1.1.1.1", "Online", 11.2, 0.0),
            ("Localhost Web Server", "127.0.0.1", "Online", 0.4, 0.0),
            ("Internal Database Server", "192.168.1.120", "Offline", 0.0, 100.0)
        ]
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for name, ip, status, lat, loss in demo_devices:
            cursor.execute(
                "INSERT INTO devices (name, ip_address, status, latency_ms, packet_loss, last_checked) VALUES (?, ?, ?, ?, ?, ?)",
                (name, ip, status, lat, loss, now_str)
            )
        conn.commit()

    # Seed Demo Alerts if empty
    cursor.execute("SELECT COUNT(*) as cnt FROM alerts")
    if cursor.fetchone()["cnt"] == 0:
        demo_alerts = [
            ("Device Offline Detected", "Warning: Internal Database Server (192.168.1.120) is unreachable.", "critical", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            ("Network Monitoring Initialized", "System monitoring started successfully with SQLite backend.", "healthy", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            ("Gateway Ping Check", "Router 192.168.1.1 responded with healthy latency (< 5ms).", "healthy", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        ]
        for title, msg, sev, ts in demo_alerts:
            cursor.execute(
                "INSERT INTO alerts (title, message, severity, timestamp, is_resolved) VALUES (?, ?, ?, ?, 0)",
                (title, msg, sev, ts)
            )
        conn.commit()

    conn.close()


# Initialize database at startup
init_db()


def login_required(f):
    """Decorator to protect routes requiring authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            flash("Please log in to access the Network Monitoring Dashboard.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# -------------------------------------------------------------
# NETWORK UTILITY FUNCTIONS
# -------------------------------------------------------------

def get_local_ip():
    """Returns local IP address of current machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not send actual traffic, just routes to nearest interface
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip


def get_public_ip():
    """Fetches public IP address using public API with quick timeout."""
    urls = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/ip"
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetworkMonitor/1.0"})
            with urllib.request.urlopen(req, timeout=2.0) as response:
                content = response.read().decode("utf-8").strip()
                if "{" in content:
                    data = json.loads(content)
                    return data.get("ip", "Unavailable")
                return content
        except Exception:
            continue
    return "Unavailable"


def resolve_host(target):
    """Safely resolves hostname to IP address."""
    clean_target = str(target).strip()
    try:
        ip = socket.gethostbyname(clean_target)
        return ip
    except Exception:
        return clean_target


def ping_host(target):
    """
    Pings a target host (IP or domain name).
    Works on Windows, Linux, and macOS.
    Returns: dict with reachability, latency (ms), packet loss (%), and raw output.
    """
    clean_target = str(target).strip()
    if not clean_target:
        return {
            "reachable": False,
            "target": target,
            "ip": "Unknown",
            "latency_ms": 0.0,
            "packet_loss": 100.0,
            "raw": "Error: Empty target specified."
        }

    resolved_ip = resolve_host(clean_target)
    is_win = platform.system().lower() == "windows"

    # Command parameters
    if is_win:
        cmd = ["ping", "-n", "2", "-w", "1000", clean_target]
    else:
        cmd = ["ping", "-c", "2", "-W", "1", clean_target]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        output = result.stdout + "\n" + result.stderr

        # Check for destination host unreachable / timed out / host not found
        low_out = output.lower()
        if "could not find host" in low_out or "unknown host" in low_out:
            return {
                "reachable": False,
                "target": clean_target,
                "ip": resolved_ip,
                "latency_ms": 0.0,
                "packet_loss": 100.0,
                "raw": output.strip() or "Ping request could not find host."
            }

        # Parse Packet Loss
        loss_match = re.search(r"\((\d+)%\s*loss\)", output, re.IGNORECASE)
        if not loss_match:
            loss_match = re.search(r"(\d+)%\s*packet loss", output, re.IGNORECASE)
        packet_loss = float(loss_match.group(1)) if loss_match else (0.0 if result.returncode == 0 else 100.0)

        # Parse Latency
        latency = 0.0
        avg_match = re.search(r"Average\s*=\s*(\d+)ms", output, re.IGNORECASE)
        if avg_match:
            latency = float(avg_match.group(1))
        else:
            time_match = re.search(r"time[=<]\s*(\d+)ms", output, re.IGNORECASE)
            if time_match:
                latency = float(time_match.group(1))
            else:
                # Unix format (e.g. rtt min/avg/max/mdev = 12.3/14.5/16.1 ms)
                unix_rtt = re.search(r"=\s*[\d\.]+/([\d\.]+)/", output)
                if unix_rtt:
                    latency = float(unix_rtt.group(1))

        # Check reachability
        reachable = (packet_loss < 100.0) and (result.returncode == 0 or latency > 0 or "reply from" in low_out)

        return {
            "reachable": reachable,
            "target": clean_target,
            "ip": resolved_ip,
            "latency_ms": round(latency, 2),
            "packet_loss": round(packet_loss, 1),
            "raw": output.strip()
        }

    except subprocess.TimeoutExpired:
        return {
            "reachable": False,
            "target": clean_target,
            "ip": resolved_ip,
            "latency_ms": 0.0,
            "packet_loss": 100.0,
            "raw": "Ping timeout expired (Host did not reply within limit)."
        }
    except Exception as e:
        return {
            "reachable": False,
            "target": clean_target,
            "ip": resolved_ip,
            "latency_ms": 0.0,
            "packet_loss": 100.0,
            "raw": f"Error running ping command: {str(e)}"
        }


def format_bytes(byte_count):
    """Converts raw byte count into human-readable MB / GB."""
    if byte_count is None:
        return "0.00 MB"
    mb = byte_count / (1024 * 1024)
    if mb > 1024:
        return f"{mb / 1024:.2f} GB"
    return f"{mb:.2f} MB"


def get_bandwidth_metrics():
    """
    Calculates current download & upload rates and total traffic counters
    using psutil.net_io_counters().
    """
    global _last_io_counters, _last_io_time, _traffic_history

    if not psutil:
        return {
            "download_speed": "0.00 KB/s",
            "upload_speed": "0.00 KB/s",
            "download_rate_raw": 0.0,
            "upload_rate_raw": 0.0,
            "total_received": "Unavailable",
            "total_sent": "Unavailable",
            "is_simulated": True
        }

    try:
        current_io = psutil.net_io_counters()
        current_time = time.time()

        download_rate_kbs = 0.0
        upload_rate_kbs = 0.0

        if _last_io_counters is not None and _last_io_time is not None:
            time_delta = current_time - _last_io_time
            if time_delta > 0:
                bytes_recv_delta = max(0, current_io.bytes_recv - _last_io_counters.bytes_recv)
                bytes_sent_delta = max(0, current_io.bytes_sent - _last_io_counters.bytes_sent)
                download_rate_kbs = (bytes_recv_delta / 1024.0) / time_delta
                upload_rate_kbs = (bytes_sent_delta / 1024.0) / time_delta

        _last_io_counters = current_io
        _last_io_time = current_time

        # Update rolling traffic history
        time_label = datetime.now().strftime("%H:%M:%S")
        _traffic_history.append({
            "time": time_label,
            "download_kb": round(download_rate_kbs, 2),
            "upload_kb": round(upload_rate_kbs, 2)
        })
        if len(_traffic_history) > 15:
            _traffic_history.pop(0)

        # Format display string
        if download_rate_kbs > 1024:
            down_str = f"{download_rate_kbs / 1024:.2f} MB/s"
        else:
            down_str = f"{download_rate_kbs:.2f} KB/s"

        if upload_rate_kbs > 1024:
            up_str = f"{upload_rate_kbs / 1024:.2f} MB/s"
        else:
            up_str = f"{upload_rate_kbs:.2f} KB/s"

        return {
            "download_speed": down_str,
            "upload_speed": up_str,
            "download_rate_raw": round(download_rate_kbs, 2),
            "upload_rate_raw": round(upload_rate_kbs, 2),
            "total_received": format_bytes(current_io.bytes_recv),
            "total_sent": format_bytes(current_io.bytes_sent),
            "is_simulated": False
        }
    except Exception as e:
        return {
            "download_speed": "0.00 KB/s",
            "upload_speed": "0.00 KB/s",
            "download_rate_raw": 0.0,
            "upload_rate_raw": 0.0,
            "total_received": "Unavailable",
            "total_sent": "Unavailable",
            "is_simulated": True,
            "error": str(e)
        }


def add_alert(title, message, severity="warning"):
    """Inserts a new alert into the database if not an immediate duplicate."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        # Avoid duplicate alert within the last 3 minutes
        cursor.execute(
            "SELECT id FROM alerts WHERE title = ? AND message = ? AND is_resolved = 0 ORDER BY id DESC LIMIT 1",
            (title, message)
        )
        if not cursor.fetchone():
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "INSERT INTO alerts (title, message, severity, timestamp, is_resolved) VALUES (?, ?, ?, ?, 0)",
                (title, message, severity, now_str)
            )
            conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error creating alert: {e}")


def log_network_check(target, ip_address, status, latency_ms, packet_loss):
    """Records a network check into the network_logs table."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO network_logs (target, ip_address, status, latency_ms, packet_loss, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (target, ip_address, status, latency_ms, packet_loss, now_str)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging network check: {e}")


# -------------------------------------------------------------
# APPLICATION VIEW ROUTES
# -------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles admin authentication with password hashing and session tracking."""
    if "user" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user"] = {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"]
            }
            flash("Logged in successfully. Welcome to the Network Dashboard!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials! For demo: username 'admin', password 'admin123'.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Logs the user out and clears session state."""
    session.clear()
    flash("You have been successfully logged out.", "info")
    return redirect(url_for("login"))


@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    """Main dashboard displaying network metrics, summary cards, and charts."""
    return render_template("dashboard.html", active_page="dashboard", user=session.get("user"))


@app.route("/devices")
@login_required
def devices():
    """Displays monitored devices table and management forms."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY id ASC")
    device_rows = cursor.fetchall()
    conn.close()
    return render_template("devices.html", active_page="devices", devices=device_rows, user=session.get("user"))


@app.route("/monitor")
@login_required
def monitor():
    """Ping & Latency Diagnostic utility page."""
    return render_template("monitor.html", active_page="monitor", user=session.get("user"))


@app.route("/history")
@login_required
def history():
    """Displays previous monitoring checks and latency logs."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM network_logs ORDER BY id DESC LIMIT 100")
    logs = cursor.fetchall()
    conn.close()
    return render_template("history.html", active_page="history", logs=logs, user=session.get("user"))


@app.route("/alerts")
@login_required
def alerts():
    """Displays network alerts and notifications."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
    alert_rows = cursor.fetchall()
    conn.close()
    return render_template("alerts.html", active_page="alerts", alerts=alert_rows, user=session.get("user"))


@app.route("/about")
@login_required
def about():
    """Educational page explaining Network Monitoring and Computer Networks concepts."""
    return render_template("about.html", active_page="about", user=session.get("user"))


# -------------------------------------------------------------
# JSON API ENDPOINTS
# -------------------------------------------------------------

@app.route("/api/network-status", methods=["GET"])
@login_required
def api_network_status():
    """
    Returns aggregated real-time network status:
    local IP, public IP, ping to primary DNS (8.8.8.8), bandwidth rates, device counts.
    """
    local_ip = get_local_ip()
    public_ip = get_public_ip()
    bandwidth = get_bandwidth_metrics()

    # Internet ping check against reliable DNS server
    ping_res = ping_host("8.8.8.8")
    is_online = ping_res["reachable"]

    # Retrieve device metrics from database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as total FROM devices")
    total_devices = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as online FROM devices WHERE status = 'Online'")
    online_devices = cursor.fetchone()["online"]

    cursor.execute("SELECT COUNT(*) as unresolved FROM alerts WHERE is_resolved = 0")
    active_alerts = cursor.fetchone()["unresolved"]
    conn.close()

    # Generate alerts based on status
    if not is_online:
        add_alert("Internet Connectivity Lost", "Internet connection is offline. Failed ping to 8.8.8.8.", "critical")
    elif ping_res["latency_ms"] > 150.0:
        add_alert("High Latency Warning", f"Internet response latency is high ({ping_res['latency_ms']} ms).", "warning")
    elif ping_res["packet_loss"] > 0:
        add_alert("Packet Loss Detected", f"Packet loss detected ({ping_res['packet_loss']}%) during internet test.", "warning")

    return jsonify({
        "status": "Online" if is_online else "Offline",
        "local_ip": local_ip,
        "public_ip": public_ip,
        "latency_ms": ping_res["latency_ms"],
        "packet_loss": ping_res["packet_loss"],
        "download_speed": bandwidth["download_speed"],
        "upload_speed": bandwidth["upload_speed"],
        "total_received": bandwidth["total_received"],
        "total_sent": bandwidth["total_sent"],
        "total_devices": total_devices,
        "online_devices": online_devices,
        "offline_devices": total_devices - online_devices,
        "active_alerts": active_alerts,
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route("/api/ping", methods=["POST"])
@login_required
def api_ping():
    """Executes a ping check against a target host and returns formatted metrics."""
    data = request.get_json(silent=True) or request.form
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"success": False, "error": "Please provide a valid hostname or IP address."}), 400

    ping_result = ping_host(target)

    status_str = "Reachable" if ping_result["reachable"] else "Unreachable"

    # Log to SQLite
    log_network_check(
        target=ping_result["target"],
        ip_address=ping_result["ip"],
        status=status_str,
        latency_ms=ping_result["latency_ms"],
        packet_loss=ping_result["packet_loss"]
    )

    # Check alert conditions
    if not ping_result["reachable"]:
        add_alert(
            "Host Unreachable",
            f"Host {ping_result['target']} ({ping_result['ip']}) is unreachable.",
            "critical"
        )
    elif ping_result["packet_loss"] > 0:
        add_alert(
            "Packet Loss on Target",
            f"{ping_result['packet_loss']}% packet loss to {ping_result['target']}.",
            "warning"
        )
    elif ping_result["latency_ms"] > 150:
        add_alert(
            "High Latency on Target",
            f"High round-trip time ({ping_result['latency_ms']} ms) to {ping_result['target']}.",
            "warning"
        )

    return jsonify({
        "success": True,
        "target": ping_result["target"],
        "ip": ping_result["ip"],
        "status": status_str,
        "reachable": ping_result["reachable"],
        "latency_ms": ping_result["latency_ms"],
        "packet_loss": ping_result["packet_loss"],
        "raw": ping_result["raw"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route("/api/devices", methods=["GET"])
@login_required
def api_devices():
    """Returns JSON list of all monitored devices."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY id ASC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"success": True, "devices": rows})


@app.route("/api/add-device", methods=["POST"])
@login_required
def api_add_device():
    """Adds a new monitored device and immediately tests reachability."""
    data = request.get_json(silent=True) or request.form
    name = data.get("name", "").strip()
    ip = data.get("ip_address", "").strip()

    if not name or not ip:
        return jsonify({"success": False, "error": "Device name and IP address/hostname are required."}), 400

    # Ping immediately
    ping_res = ping_host(ip)
    status_str = "Online" if ping_res["reachable"] else "Offline"
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO devices (name, ip_address, status, latency_ms, packet_loss, last_checked) VALUES (?, ?, ?, ?, ?, ?)",
        (name, ip, status_str, ping_res["latency_ms"], ping_res["packet_loss"], now_str)
    )
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Log and trigger alert if unreachable
    log_network_check(name, ping_res["ip"], status_str, ping_res["latency_ms"], ping_res["packet_loss"])
    if not ping_res["reachable"]:
        add_alert("Device Offline", f"Warning: Newly added device '{name}' ({ip}) is unreachable.", "critical")

    return jsonify({
        "success": True,
        "message": f"Device '{name}' added successfully.",
        "device": {
            "id": new_id,
            "name": name,
            "ip_address": ip,
            "status": status_str,
            "latency_ms": ping_res["latency_ms"],
            "packet_loss": ping_res["packet_loss"],
            "last_checked": now_str
        }
    })


@app.route("/api/check-device/<int:device_id>", methods=["POST"])
@login_required
def api_check_device(device_id):
    """Pings a specific device and updates its status in the database."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    device = cursor.fetchone()

    if not device:
        conn.close()
        return jsonify({"success": False, "error": "Device not found."}), 404

    ping_res = ping_host(device["ip_address"])
    status_str = "Online" if ping_res["reachable"] else "Offline"
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        "UPDATE devices SET status = ?, latency_ms = ?, packet_loss = ?, last_checked = ? WHERE id = ?",
        (status_str, ping_res["latency_ms"], ping_res["packet_loss"], now_str, device_id)
    )
    conn.commit()
    conn.close()

    log_network_check(device["name"], ping_res["ip"], status_str, ping_res["latency_ms"], ping_res["packet_loss"])
    if not ping_res["reachable"]:
        add_alert("Device Unreachable", f"Warning: Device '{device['name']}' ({device['ip_address']}) is unreachable.", "critical")

    return jsonify({
        "success": True,
        "device": {
            "id": device_id,
            "name": device["name"],
            "ip_address": device["ip_address"],
            "status": status_str,
            "latency_ms": ping_res["latency_ms"],
            "packet_loss": ping_res["packet_loss"],
            "last_checked": now_str
        }
    })


@app.route("/api/check-all-devices", methods=["POST"])
@login_required
def api_check_all_devices():
    """Pings all monitored devices in batch and updates their database entries."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices")
    devices = cursor.fetchall()

    updated = []
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for dev in devices:
        ping_res = ping_host(dev["ip_address"])
        status_str = "Online" if ping_res["reachable"] else "Offline"

        cursor.execute(
            "UPDATE devices SET status = ?, latency_ms = ?, packet_loss = ?, last_checked = ? WHERE id = ?",
            (status_str, ping_res["latency_ms"], ping_res["packet_loss"], now_str, dev["id"])
        )
        log_network_check(dev["name"], ping_res["ip"], status_str, ping_res["latency_ms"], ping_res["packet_loss"])

        if not ping_res["reachable"]:
            add_alert("Device Unreachable", f"Warning: {dev['name']} ({dev['ip_address']}) is unreachable.", "critical")

        updated.append({
            "id": dev["id"],
            "name": dev["name"],
            "ip_address": dev["ip_address"],
            "status": status_str,
            "latency_ms": ping_res["latency_ms"],
            "packet_loss": ping_res["packet_loss"],
            "last_checked": now_str
        })

    conn.commit()
    conn.close()

    return jsonify({"success": True, "count": len(updated), "devices": updated})


@app.route("/api/delete-device/<int:device_id>", methods=["POST", "DELETE"])
@login_required
def api_delete_device(device_id):
    """Deletes a device from monitoring."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Device deleted successfully."})


@app.route("/api/traffic", methods=["GET"])
@login_required
def api_traffic():
    """Returns rolling traffic data series for Chart.js real-time charts."""
    metrics = get_bandwidth_metrics()
    return jsonify({
        "success": True,
        "current": metrics,
        "history": _traffic_history
    })


@app.route("/api/alerts", methods=["GET"])
@login_required
def api_alerts():
    """Returns JSON list of alerts."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
    alert_rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"success": True, "alerts": alert_rows})


@app.route("/api/resolve-alert/<int:alert_id>", methods=["POST"])
@login_required
def api_resolve_alert(alert_id):
    """Marks an alert as resolved."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET is_resolved = 1 WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Alert marked as resolved."})


@app.route("/api/clear-alerts", methods=["POST"])
@login_required
def api_clear_alerts():
    """Clears all alerts from the database."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "All alerts cleared successfully."})


@app.route("/api/clear-history", methods=["POST"])
@login_required
def api_clear_history():
    """Clears monitoring history logs from the database."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM network_logs")
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Monitoring history cleared."})


# -------------------------------------------------------------
# RUN APPLICATION
# -------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print(" Cloud-Based Network Monitoring Dashboard")
    print(" College Project - Computer Networks Lab")
    print("=" * 60)
    print(f" Local IP : {get_local_ip()}")
    print(" Starting server on http://127.0.0.1:5000")
    print(" Default Admin Credentials -> username: admin | password: admin123")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True)
