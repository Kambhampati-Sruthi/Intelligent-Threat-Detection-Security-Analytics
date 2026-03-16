from fastapi import FastAPI, UploadFile, File
import pandas as pd
import io

from backend.attack_predictor import predict_attack
from backend.ip_blocker import block_ip, blocked_ips

app = FastAPI(
    title="SentinelAI Security Engine",
    description="AI Powered Cyber Threat Detection API",
    version="1.0"
)

# ------------------------------------------------
# HEALTH CHECK
# ------------------------------------------------

@app.get("/health")
def health():
    return {"status": "SentinelAI Backend Running"}

# ------------------------------------------------
# LOG ANALYSIS (MAIN AI DETECTION)
# ------------------------------------------------

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):

    content = await file.read()

    df = pd.read_csv(io.StringIO(content.decode()))

    alerts = []

    for index, row in df.iterrows():

        status = predict_attack(row["failed_logins"])

        if status != "NORMAL":

            alert = {
                "ip": row["ip"],
                "failed_logins": int(row["failed_logins"]),
                "status": status
            }

            alerts.append(alert)

            if status == "HIGH RISK ATTACK":
                block_ip(row["ip"])

    return {
        "total_logs": len(df),
        "alerts": alerts
    }

# ------------------------------------------------
# BLOCKED IPS
# ------------------------------------------------

@app.get("/blocked-ips")
def get_blocked():

    return {
        "blocked_ips": blocked_ips
    }

# ------------------------------------------------
# THREAT INTELLIGENCE FEED
# ------------------------------------------------

@app.get("/threat-feed")
def threat_feed():

    return [
        {"threat": "Brute Force Attack", "severity": "High"},
        {"threat": "Phishing Campaign", "severity": "Medium"},
        {"threat": "Malware Command & Control", "severity": "Critical"},
        {"threat": "Credential Stuffing", "severity": "High"},
        {"threat": "Ransomware Activity", "severity": "Critical"}
    ]

# ------------------------------------------------
# DARK WEB CHECK (SIMULATED)
# ------------------------------------------------

@app.get("/darkweb-check")
def darkweb(email: str):

    if "test" in email.lower():

        return {
            "email": email,
            "status": "leaked",
            "source": "Dark Web Breach Database"
        }

    return {
        "email": email,
        "status": "safe"
    }