import os
import json
import logging
import random
import ipaddress
from flask import Flask, request, jsonify, send_file
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import pandas as pd
import numpy as np

app = Flask(__name__)

# Create directories for logs and static files
if not os.path.exists("logs"):
    os.makedirs("logs")
if not os.path.exists("static"):
    os.makedirs("static")

LOG_FILE = "logs/attacks.log"
IP_BLACKLIST_FILE = "logs/blacklist.json"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

# Risk levels for different types of attacks
RISK_LEVELS = {
    "SQL Injection": 5,
    "XSS Attack": 4,
    "Brute Force": 3,
    "Port Scan": 2,
    "Command Injection": 4,
    "Path Traversal": 3,
    "File Inclusion": 4,
    "Other": 1
}

# IP tracking and blacklisting
ip_activity = {}
blacklisted_ips = set()

# Load existing blacklist if available
if os.path.exists(IP_BLACKLIST_FILE):
    try:
        with open(IP_BLACKLIST_FILE, "r") as f:
            blacklisted_ips = set(json.load(f))
    except json.JSONDecodeError:
        blacklisted_ips = set()

# Function to log attacker activity with enhanced tracking
def log_attack(ip, attack_type, payload, url_path):
    # Calculate risk level
    risk = RISK_LEVELS.get(attack_type, 1)
    
    # Track IP activity
    if ip not in ip_activity:
        ip_activity[ip] = {
            "first_seen": datetime.now(),
            "attack_count": 0,
            "risk_score": 0,
            "attack_types": set()
        }
    
    ip_activity[ip]["attack_count"] += 1
    ip_activity[ip]["attack_types"].add(attack_type)
    ip_activity[ip]["risk_score"] += risk
    ip_activity[ip]["last_seen"] = datetime.now()
    
    # Blacklist IPs with high risk scores or repeated attacks
    if ip_activity[ip]["risk_score"] >= 10 or ip_activity[ip]["attack_count"] >= 5:
        blacklisted_ips.add(ip)
        # Save updated blacklist
        with open(IP_BLACKLIST_FILE, "w") as f:
            json.dump(list(blacklisted_ips), f)
    
    # Create log entry
    log_entry = {
        "timestamp": str(datetime.now()),
        "ip": ip,
        "attack_type": attack_type,
        "payload": payload,
        "url_path": url_path,
        "risk_level": risk,
        "cumulative_risk": ip_activity[ip]["risk_score"],
        "blacklisted": ip in blacklisted_ips
    }

    # Log to console for debugging
    logging.info(f"Attack detected - IP: {ip}, Type: {attack_type}, Risk: {risk}")
    
    # Save log to file
    with open(LOG_FILE, "a") as log_file:
        json.dump(log_entry, log_file)
        log_file.write("\n")  # Ensure proper newline separation

    return risk, ip in blacklisted_ips

# Function to detect attack types based on payload patterns
def detect_attack_type(payload, url_path, method):
    if isinstance(payload, dict):
        payload_str = str(payload)
    else:
        payload_str = str(payload)
    
    # SQL Injection patterns
    sql_patterns = ["SELECT", "UNION", "DROP TABLE", "DELETE FROM", "INSERT INTO", 
                    "1=1", "OR 1=1", "--", "/*", "*/", "';", "' OR '", "EXEC", "EXECUTE"]
    
    # XSS patterns
    xss_patterns = ["<script>", "javascript:", "onerror=", "onload=", "eval(", "document.cookie", 
                    "alert(", "<img", "<iframe", "onmouseover"]
    
    # Command injection patterns
    cmd_patterns = [";", "&&", "||", "`", "$", "$(", "bash", "sh ", "/bin/", "curl", "wget", "nc ", "netcat"]
    
    # Path traversal patterns
    path_patterns = ["../", "..\\", "/etc/passwd", "boot.ini", "win.ini", "system32", "/var/www"]
    
    # File inclusion patterns
    file_patterns = ["php://", "file://", "include(", "require(", "include_once", "data://"]
    
    # Brute force detection for login endpoints
    brute_force = False
    if "/login" in url_path and method == "POST":
        if isinstance(payload, dict):
            if "password" in payload and (len(str(payload["password"])) < 6 or payload["password"] in ["password", "123456", "admin"]):
                brute_force = True
    
    # Check for patterns
    for pattern in sql_patterns:
        if pattern in payload_str.upper():
            return "SQL Injection"
    
    for pattern in xss_patterns:
        if pattern in payload_str.lower():
            return "XSS Attack"
    
    for pattern in cmd_patterns:
        if pattern in payload_str:
            return "Command Injection"
    
    for pattern in path_patterns:
        if pattern in payload_str:
            return "Path Traversal"
    
    for pattern in file_patterns:
        if pattern in payload_str.lower():
            return "File Inclusion"
    
    if brute_force:
        return "Brute Force"
    
    if "/portscan" in url_path:
        return "Port Scan"
    
    return "Other"

# Middleware to check if IP is blacklisted
@app.before_request
def check_if_blacklisted():
    ip = request.remote_addr
    if ip in blacklisted_ips:
        # Log the blocked attempt
        logging.info(f"Blocked request from blacklisted IP: {ip}")
        return jsonify({"message": "Access Forbidden", "status": 403}), 403

# Enhanced honeypot endpoints
@app.route("/login", methods=["POST"])
def fake_login():
    ip = request.remote_addr
    data = request.json or {}
    
    attack_type = detect_attack_type(data, "/login", "POST")
    risk, blacklisted = log_attack(ip, attack_type, data, "/login")
    
    if blacklisted:
        return jsonify({"message": "Access Forbidden", "risk_level": risk}), 403
    
    # Simulate a vulnerable login system
    time_delay = random.uniform(0.5, 2.0)  # Random delay to seem more realistic
    return jsonify({
        "message": "Invalid credentials", 
        "status": "error", 
        "risk_level": risk
    }), 401

@app.route("/search", methods=["GET"])
def fake_search():
    ip = request.remote_addr
    query = request.args.get("q", "")
    
    attack_type = detect_attack_type(query, "/search", "GET")
    risk, blacklisted = log_attack(ip, attack_type, query, "/search")
    
    if blacklisted:
        return jsonify({"message": "Access Forbidden", "risk_level": risk}), 403
    
    # Return "results" to keep attacker engaged
    return jsonify({
        "message": "No results found for your query", 
        "query": query,
        "results": [],
        "risk_level": risk
    })

@app.route("/api/query", methods=["POST"])
def fake_db():
    ip = request.remote_addr
    data = request.json or {}
    
    attack_type = detect_attack_type(data, "/api/query", "POST")
    risk, blacklisted = log_attack(ip, attack_type, data, "/api/query")
    
    if blacklisted:
        return jsonify({"message": "Access Forbidden", "risk_level": risk}), 403
    
    # Simulate a database error that leaks information
    return jsonify({
        "message": "Database Error: Invalid SQL syntax", 
        "error_code": "DB-" + str(random.randint(1000, 9999)),
        "risk_level": risk
    }), 500

@app.route("/admin", methods=["GET", "POST"])
def fake_admin():
    ip = request.remote_addr
    
    if request.method == "GET":
        payload = dict(request.args)
    else:
        payload = request.json or {}
    
    attack_type = detect_attack_type(payload, "/admin", request.method)
    risk, blacklisted = log_attack(ip, attack_type, payload, "/admin")
    
    if blacklisted:
        return jsonify({"message": "Access Forbidden", "risk_level": risk}), 403
    
    # Simulate an admin panel
    return jsonify({
        "message": "Admin access denied", 
        "auth_required": True,
        "risk_level": risk
    }), 401

@app.route("/upload", methods=["POST"])
def fake_upload():
    ip = request.remote_addr
    data = request.form.to_dict()
    
    attack_type = detect_attack_type(data, "/upload", "POST")
    risk, blacklisted = log_attack(ip, attack_type, data, "/upload")
    
    if blacklisted:
        return jsonify({"message": "Access Forbidden", "risk_level": risk}), 403
    
    # Simulate file upload vulnerability
    return jsonify({
        "message": "Upload failed: Invalid file type", 
        "allowed_types": ["jpg", "png", "pdf"],
        "risk_level": risk
    }), 400

@app.route("/portscan", methods=["GET"])
def fake_port():
    ip = request.remote_addr
    attack_type = "Port Scan"
    
    risk, blacklisted = log_attack(ip, attack_type, "Port scanning activity detected", "/portscan")
    
    if blacklisted:
        return jsonify({"message": "Access Forbidden", "risk_level": risk}), 403
    
    # Simulate open ports to encourage more scanning
    return jsonify({
        "message": "System Information", 
        "ports": [
            {"port": 22, "service": "SSH"},
            {"port": 80, "service": "HTTP"},
            {"port": 443, "service": "HTTPS"}
        ],
        "risk_level": risk
    })

# Enhanced routes for analysis and visualization
@app.route("/dashboard", methods=["GET"])
def dashboard():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Honeypot Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #333; }
            .container { display: flex; flex-wrap: wrap; }
            .graph { margin: 10px; border: 1px solid #ddd; padding: 10px; }
        </style>
    </head>
    <body>
        <h1>Honeypot Attack Analysis Dashboard</h1>
        <div class="container">
            <div class="graph">
                <h2>Attacks by Risk Level</h2>
                <img src="/graph/risk" width="600" height="400">
            </div>
            <div class="graph">
                <h2>Attacks by Type</h2>
                <img src="/graph/types" width="600" height="400">
            </div>
            <div class="graph">
                <h2>Attack Timeline</h2>
                <img src="/graph/timeline" width="600" height="400">
            </div>
        </div>
    </body>
    </html>
    """
    return html

@app.route("/graph/risk", methods=["GET"])
def generate_risk_graph():
    # Read log file and parse data
    risk_data = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as log_file:
            for line in log_file:
                try:
                    log_entry = json.loads(line.strip())
                    risk_level = log_entry.get("risk_level", 1)
                    if risk_level in risk_data:
                        risk_data[risk_level] += 1
                except json.JSONDecodeError:
                    continue
    
    # Generate graph
    plt.figure(figsize=(10, 6))
    risk_labels = ["Very Low (1)", "Low (2)", "Medium (3)", "High (4)", "Critical (5)"]
    colors = ["green", "blue", "yellow", "orange", "red"]
    
    plt.bar(risk_labels, [risk_data[i] for i in range(1, 6)], color=colors)
    plt.xlabel("Risk Level")
    plt.ylabel("Number of Attacks")
    plt.title("Honeypot Attacks by Risk Level")
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    # Save and serve the graph
    graph_path = "static/risk_graph.png"
    plt.savefig(graph_path)
    plt.close()
    
    return send_file(graph_path, mimetype="image/png")

@app.route("/graph/types", methods=["GET"])
def generate_types_graph():
    # Read log file and parse data
    attack_types = {key: 0 for key in RISK_LEVELS.keys()}
    
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as log_file:
            for line in log_file:
                try:
                    log_entry = json.loads(line.strip())
                    attack_type = log_entry.get("attack_type", "Other")
                    if attack_type in attack_types:
                        attack_types[attack_type] += 1
                except json.JSONDecodeError:
                    continue
    
    # Generate graph
    plt.figure(figsize=(10, 6))
    
    # Sort by frequency
    sorted_types = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)
    types = [x[0] for x in sorted_types]
    counts = [x[1] for x in sorted_types]
    
    # Color based on risk level
    colors = [plt.cm.RdYlGn_r(RISK_LEVELS[t]/5.0) for t in types]
    
    plt.bar(types, counts, color=colors)
    plt.xlabel("Attack Type")
    plt.ylabel("Number of Attempts")
    plt.title("Honeypot Attack Types")
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    # Save and serve the graph
    graph_path = "static/types_graph.png"
    plt.savefig(graph_path)
    plt.close()
    
    return send_file(graph_path, mimetype="image/png")

@app.route("/graph/timeline", methods=["GET"])
def generate_timeline_graph():
    # Read log file and parse data
    timestamps = []
    risk_levels = []
    
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as log_file:
            for line in log_file:
                try:
                    log_entry = json.loads(line.strip())
                    timestamp = datetime.fromisoformat(log_entry.get("timestamp").split("+")[0])
                    risk = log_entry.get("risk_level", 1)
                    
                    timestamps.append(timestamp)
                    risk_levels.append(risk)
                except (json.JSONDecodeError, ValueError):
                    continue
    
    # If we have data, generate timeline
    if timestamps:
        # Convert to pandas for easier handling
        df = pd.DataFrame({"timestamp": timestamps, "risk": risk_levels})
        df = df.sort_values("timestamp")
        
        # Generate graph
        plt.figure(figsize=(12, 6))
        
        # Plot with color based on risk level
        scatter = plt.scatter(df["timestamp"], df["risk"], 
                             c=df["risk"], cmap="RdYlGn_r", 
                             alpha=0.7, s=50)
        
        # Add trend line
        if len(df) > 1:
            z = np.polyfit(range(len(df)), df["risk"], 1)
            p = np.poly1d(z)
            plt.plot(df["timestamp"], p(range(len(df))), "r--", linewidth=2)
        
        plt.colorbar(scatter, label="Risk Level")
        plt.xlabel("Time")
        plt.ylabel("Risk Level")
        plt.title("Attack Risk Timeline")
        plt.ylim(0.5, 5.5)  # Set y-axis limits to match risk levels
        plt.yticks([1, 2, 3, 4, 5])
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        
        # Save and serve the graph
        graph_path = "static/timeline_graph.png"
        plt.savefig(graph_path)
        plt.close()
        
        return send_file(graph_path, mimetype="image/png")
    else:
        # If no data, return empty graph
        plt.figure(figsize=(10, 6))
        plt.text(0.5, 0.5, "No timeline data available", 
                horizontalalignment="center", verticalalignment="center")
        plt.xlabel("Time")
        plt.ylabel("Risk Level")
        plt.title("Attack Risk Timeline")
        plt.tight_layout()
        
        graph_path = "static/timeline_graph.png"
        plt.savefig(graph_path)
        plt.close()
        
        return send_file(graph_path, mimetype="image/png")

# Statistics API endpoint
@app.route("/api/stats", methods=["GET"])
def get_stats():
    stats = {
        "total_attacks": 0,
        "unique_ips": 0,
        "blacklisted_ips": len(blacklisted_ips),
        "attacks_by_type": {},
        "attacks_by_risk": {1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
        "highest_risk_ips": []
    }
    
    # Parse log file
    if os.path.exists(LOG_FILE):
        unique_ips = set()
        ip_risk = {}
        
        with open(LOG_FILE, "r") as log_file:
            for line in log_file:
                try:
                    log_entry = json.loads(line.strip())
                    stats["total_attacks"] += 1
                    
                    ip = log_entry.get("ip", "unknown")
                    unique_ips.add(ip)
                    
                    attack_type = log_entry.get("attack_type", "Other")
                    if attack_type not in stats["attacks_by_type"]:
                        stats["attacks_by_type"][attack_type] = 0
                    stats["attacks_by_type"][attack_type] += 1
                    
                    risk_level = log_entry.get("risk_level", 1)
                    stats["attacks_by_risk"][risk_level] += 1
                    
                    # Track IP risk scores
                    if ip not in ip_risk:
                        ip_risk[ip] = 0
                    ip_risk[ip] += risk_level
                    
                except json.JSONDecodeError:
                    continue
        
        stats["unique_ips"] = len(unique_ips)
        
        # Get top 5 highest risk IPs
        top_ips = sorted(ip_risk.items(), key=lambda x: x[1], reverse=True)[:5]
        stats["highest_risk_ips"] = [{"ip": ip, "risk_score": score} for ip, score in top_ips]
    
    return jsonify(stats)

if __name__ == "__main__":
    # Print startup message
    print(f"Honeypot server starting on port 5000...")
    print(f"Dashboard available at http://localhost:5000/dashboard")
    print(f"Log file: {LOG_FILE}")
    app.run(host="0.0.0.0", port=5000, debug=True)