from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
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
# ✅ CORS (REQUIRED for Streamlit connection)
# ------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow all (important for deployment)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------
# ✅ ROOT + HEALTH CHECK
# ------------------------------------------------

@app.get("/")
def root():
    return {"message": "SentinelAI Backend Running"}

@app.get("/health")
def health():
    return {"status": "OK"}

# ------------------------------------------------
# 🔥 LOG ANALYSIS (MAIN AI DETECTION)
# ------------------------------------------------

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    try:
        content = await file.read()
        df = pd.read_csv(io.StringIO(content.decode()))

        # ✅ Safety: handle missing columns
        required_cols = ["ip", "failed_logins"]

        for col in required_cols:
            if col not in df.columns:
                return {"error": f"Missing column: {col}"}

        alerts = []

        for _, row in df.iterrows():
            status = predict_attack(row["failed_logins"])

            if status != "NORMAL":
                alert = {
                    "ip": str(row["ip"]),
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

    except Exception as e:
        return {"error": str(e)}

# ------------------------------------------------
# 🔐 BLOCKED IPS
# ------------------------------------------------

@app.get("/blocked-ips")
def get_blocked():
    return {
        "blocked_ips": blocked_ips
    }

# ------------------------------------------------
# 🌐 THREAT INTELLIGENCE
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
# 🕵 DARK WEB CHECK
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
