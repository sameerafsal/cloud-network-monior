# Cloud-Based Network Monitoring Dashboard

A modern, beginner-friendly, and interactive web dashboard designed for Computer Networks lab demonstration and evaluation. Built with **Python Flask**, **SQLite**, and **Chart.js**, this project monitors real-time network health, round-trip latency, packet loss, bandwidth consumption, and individual network nodes.

---

## 1. Project Objective

The objective of this project is to build an intuitive Network Operations Center (NOC) dashboard that translates abstract Computer Networks concepts into interactive visual metrics. It allows students and administrators to:
- Monitor local network interface configurations and external WAN connectivity.
- Diagnose network latency and packet loss using ICMP echo requests (ping).
- Track real-time bandwidth (download and upload throughput).
- Maintain an inventory of monitored network devices (routers, servers, DNS).
- Log incidents, threshold violations, and historical telemetry into an SQLite database.
- Demonstrate cloud readiness using 12-factor application architecture principles.

---

## 2. Key Features

- **Admin Authentication**: Secure login portal with password hashing (`werkzeug.security`) and session tracking.
- **Real-Time Network Statistics**:
  - Network Status (Online / Offline)
  - Private Local IPv4 & Public Internet IPv4 (via NAT)
  - Round-Trip Time (RTT) Latency in milliseconds
  - Transmission Packet Loss percentage
  - Real-time Download & Upload throughput (KB/s and MB/s)
  - Total cumulative data sent and received
- **Interactive Ping / Latency Diagnostic Utility**:
  - Test any hostname (`google.com`) or IP (`8.8.8.8`).
  - Cross-platform Windows & Linux ICMP probe handling.
  - View raw terminal output directly in the UI.
- **Monitored Devices Inventory**:
  - Track Routers, DNS Servers, Web Servers, and Localhost nodes.
  - Add custom devices with automatic instant connectivity checks.
  - Single-click "Check" and "Check All Devices" triggers.
- **Live Visualizations (Chart.js)**:
  - Real-time rolling network traffic line chart (sampled via `psutil`).
  - Latency trend graph over time.
  - Device health status distribution (doughnut chart).
- **Automated Alerting Engine**:
  - Color-coded severity alerts: **Green (Healthy)**, **Yellow (Warning)**, **Red (Critical)**.
  - Automatically triggered upon node unreachability, packet loss, or latency exceeding 150 ms.
- **Monitoring History & CSV Export**:
  - Audit trail of all ping checks with filter search.
  - Client-side one-click CSV export for reports and submissions.
- **Educational About Page**:
  - In-depth theoretical explanations of OSI layers, ICMP, IP routing, latency vs jitter, and bandwidth vs throughput.

---

## 3. Technology Stack

- **Backend**: Python 3.10+, Flask 3.x
- **Database**: SQLite 3 (auto-created on startup)
- **Frontend**: HTML5, CSS3 (Modern Dark Theme), Vanilla JavaScript (ES6)
- **Data Visualization**: Chart.js 4.x
- **System & Network Libraries**:
  - `socket`: Local IP address resolution and port probes.
  - `subprocess`: Safe Windows (`ping -n 2 -w 1000`) and Linux/macOS ICMP execution.
  - `psutil`: Operating system hardware NIC packet counters (`psutil.net_io_counters()`).
  - `werkzeug.security`: Secure password hashing (`generate_password_hash`, `check_password_hash`).

---

## 4. Project Folder Structure

```text
cloud-network-monitor/
│
├── app.py                  # Core Flask backend, network utilities, & REST APIs
├── requirements.txt        # Python dependency manifest
├── database.db             # Auto-generated SQLite database
│
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Main layout with responsive sidebar and topbar
│   ├── login.html          # Admin authentication portal
│   ├── dashboard.html      # Main NOC overview & Chart.js live graphs
│   ├── devices.html        # Monitored nodes table & add-device form
│   ├── monitor.html        # Interactive ping utility & terminal output
│   ├── history.html        # Historical network check logs & CSV exporter
│   ├── alerts.html         # Incident feed with resolve actions
│   └── about.html          # Computer Networks theory & architecture
│
├── static/                 # Static web assets
│   ├── css/
│   │   └── style.css       # Complete dark dashboard theme & components
│   └── js/
│       └── dashboard.js    # Chart.js scripts, AJAX polling, & event handlers
│
└── README.md               # Project documentation & viva guide
```

---

## 5. Prerequisites

- Python 3.8 or higher installed on your computer.
- Visual Studio Code (recommended) or any modern code editor.
- Active internet connection (to test DNS reachability and public IP lookups).

---

## 6. Installation & Setup (Step-by-Step for Windows & VS Code)

### Step 1: Open the Project in VS Code
1. Open **VS Code**.
2. Go to **File** → **Open Folder...**
3. Select `cloud-network-monitor`.

### Step 2: Open the Integrated Terminal
In VS Code, press `` Ctrl + ` `` (backtick) or select **Terminal** → **New Terminal** from the top menu.

### Step 3: Create a Python Virtual Environment
Run the following command in PowerShell:
```powershell
python -m venv venv
```

### Step 4: Activate the Virtual Environment
```powershell
venv\Scripts\activate
```
*(If PowerShell shows a script execution policy error, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and then run the activate command again).*

### Step 5: Install Dependencies
```powershell
pip install -r requirements.txt
```

---

## 7. How to Run the Project

With the virtual environment active, run:
```powershell
python app.py
```

You will see terminal output similar to:
```text
============================================================
 Cloud-Based Network Monitoring Dashboard
 College Project - Computer Networks Lab
============================================================
 Local IP : 192.168.1.X
 Starting server on http://127.0.0.1:5000
 Default Admin Credentials -> username: admin | password: admin123
============================================================
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
```

Open your browser and navigate to:
```text
http://127.0.0.1:5000
```

---

## 8. Demo Login Credentials

- **Username**: `admin`
- **Password**: `admin123`

*(These are seeded automatically into `database.db` with secure hashing upon first startup).*

---

## 9. Explanation of Each Module

| Module / File | Description |
| :--- | :--- |
| **`app.py`** | The central Flask application. Manages routes, session-based authentication, database initialization, network socket probing, Windows subprocess ping execution, bandwidth delta calculation, and JSON REST API endpoints. |
| **`database.db`** | An embedded relational SQLite database with 4 structured tables: `users`, `devices`, `network_logs`, and `alerts`. |
| **`templates/dashboard.html`** | The main dashboard displaying 8 real-time stat cards, bandwidth metrics, Chart.js traffic graphs, and a quick ping widget. |
| **`templates/devices.html`** | Device management console where users can monitor routers, local servers, or external nodes, test individual connectivity, or add new devices dynamically. |
| **`templates/monitor.html`** | A dedicated ICMP echo utility allowing users to ping any target host, inspect resolved IPs, measure RTT, and inspect raw subprocess terminal output. |
| **`templates/history.html`** | Complete audit log storing previous ping checks in SQLite, supporting live search filtering and client-side CSV downloads. |
| **`templates/alerts.html`** | An incident management feed classifying issues by severity (`critical`, `warning`, `healthy`) with single-click resolution. |
| **`templates/about.html`** | Comprehensive explanation of the project's architecture, data flow, and underlying networking theory. |
| **`static/js/dashboard.js`** | Manages asynchronous AJAX polling, Chart.js live dataset updates, DOM mutations, and button interactions without full-page reloads. |
| **`static/css/style.css`** | Custom, dependency-free dark mode stylesheet featuring high-contrast text, glowing indicators, responsive grids, and clean tables. |

---

## 10. Computer Networks (CN) Concepts Demonstrated

1. **IP Addressing & NAT (Network Address Translation)**:
   - **Local IP**: Resolves the internal network interface address (e.g. `192.168.x.x` or `10.x.x.x`) assigned by a DHCP server.
   - **Public IP**: Identifies the router's globally unique address assigned by the ISP, demonstrating how NAT multiplexes private addresses onto a single public IP.
2. **ICMP Protocol (Internet Control Message Protocol)**:
   - Operates at **Layer 3 (Network Layer)** of the OSI model.
   - Pings send **ICMP Type 8 (Echo Request)** packets and measure returning **ICMP Type 0 (Echo Reply)** packets.
3. **Round Trip Time (RTT) & Latency**:
   - The time elapsed in milliseconds between sending an echo request and receiving the response. Highlights propagation, transmission, and queuing delay across network hops.
4. **Packet Loss**:
   - The percentage of sent packets that failed to return. Used as an indicator of link congestion, hardware degradation, or strict firewall filtering.
5. **Bandwidth vs. Throughput**:
   - Demonstrates the difference between theoretical link speed (Bandwidth) and actual transmitted data over time (Throughput), sampled directly from OS network card counters using `psutil`.
6. **Client-Server Architecture & RESTful APIs**:
   - Illustrates the separation of concerns: A lightweight web client communicating asynchronously with a backend server over HTTP using structured JSON payloads (`GET /api/network-status`, `POST /api/ping`).

---

## 11. Cloud Concept & Deployment Readiness

Although designed to run easily in VS Code on Windows, the application adheres to 12-factor cloud deployment principles:
- **Port Binding**: Binds to `0.0.0.0:$PORT` using environment variable fallbacks.
- **Cross-Platform Compatibility**: Automatically detects whether the host OS is Windows or Linux and executes the appropriate ping syntax (`-n` vs `-c`).
- **Deployable to Modern Cloud Platforms**:
  - **Render / Railway**: Create a Web Service pointing to `gunicorn app:app` or `python app.py`.
  - **AWS EC2 / DigitalOcean**: Run inside a standard Ubuntu Linux VM or Docker container.
  - **PythonAnywhere**: Upload the directory and configure the WSGI file.

---

## 12. Future Enhancements

- **Traceroute Integration**: Visualize each intermediate router hop and latency along the route to a destination.
- **Port Scanner Tool**: Implement TCP SYN/connect scanning on common service ports (21, 22, 80, 443, 3306).
- **Email / Webhook Notifications**: Send automated alerts via SMTP or Discord/Slack webhooks when critical servers go down.
- **SNMP Protocol Support**: Gather CPU, memory, and temperature metrics from managed switches and enterprise routers.
