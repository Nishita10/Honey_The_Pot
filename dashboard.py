import dash
from dash import dcc, html
from dash.dependencies import Output, Input
import pandas as pd
import plotly.express as px
import time
import os
import re

# Log file path
LOG_FILE = "https_audits.log"  # replace with your actual log path

# Scoring rules
def calculate_score(events):
    score = 0
    failed_attempts = 0
    for event in events:
        if "Failed login attempt" in event:
            score += 2
            failed_attempts += 1
        elif "User accessed logs" in event:
            score += 3
        elif "New user registered" in event:
            score += 1
        elif "User logged in" in event and failed_attempts > 0:
            score += 2  # suspicious login after fails
        # Reset failed attempts count after successful login
        if "User logged in" in event:
            failed_attempts = 0
    return score

def parse_log():
    if not os.path.exists(LOG_FILE):
        return pd.DataFrame(columns=["Timestamp", "IP", "Event", "Username", "Score"])

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    records = []
    ip_events = {}

    for line in lines:
        # General event parsing
        timestamp_match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+", line)
        timestamp = timestamp_match.group(1) if timestamp_match else ""
        ip_match = re.search(r"IP(?: Address)?: ([\d\.]+)", line)
        ip = ip_match.group(1) if ip_match else "Unknown"
        username_match = re.search(r"Username: ([^,\n ]+)", line)
        username = username_match.group(1) if username_match else ""
        event = line.split(" - ")[-1].strip()

        if ip not in ip_events:
            ip_events[ip] = []
        ip_events[ip].append(event)

        records.append({
            "Timestamp": timestamp,
            "IP": ip,
            "Event": event,
            "Username": username
        })

    # Calculate scores per IP
    ip_scores = {ip: calculate_score(events) for ip, events in ip_events.items()}

    df = pd.DataFrame(records)
    df["Score"] = df["IP"].map(ip_scores)
    return df

# Dash app
app = dash.Dash(__name__)
app.title = "Login Behavior Dashboard"

app.layout = html.Div([
    html.H1("Login Activity & Risk Dashboard"),
    dcc.Interval(id='interval-component', interval=3000, n_intervals=0),  # Update every 3s

    html.Div([
        html.H3("Top Risky IPs"),
        dcc.Graph(id='top-ips')
    ]),

    html.Div([
        html.H3("Event Timeline"),
        dcc.Graph(id='event-timeline')
    ]),

    html.Div([
        html.H3("Risk Level Distribution"),
        dcc.Graph(id='risk-distribution')
    ])
])

@app.callback(
    Output('top-ips', 'figure'),
    Output('event-timeline', 'figure'),
    Output('risk-distribution', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_dashboard(n):
    df = parse_log()

    # Top IPs
    top_ips = df.groupby("IP").agg({"Score": "max"}).sort_values("Score", ascending=False).head(10).reset_index()
    fig_ips = px.bar(top_ips, x="IP", y="Score", title="Top Risky IPs")

    # Timeline
    fig_time = px.scatter(df, x="Timestamp", y="IP", color="Event", title="Event Timeline", size_max=10)

    # Risk Levels
    df["Risk Level"] = pd.cut(df["Score"], bins=[-1, 2, 5, 100], labels=["Low", "Medium", "High"])
    risk_dist = df.groupby("Risk Level").size().reset_index(name='Count')
    fig_risk = px.pie(risk_dist, names="Risk Level", values="Count", title="Risk Level Distribution")

    return fig_ips, fig_time, fig_risk

if __name__ == '__main__':
    app.run(debug=True)
