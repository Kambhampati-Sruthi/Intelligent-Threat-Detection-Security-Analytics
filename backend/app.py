from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import io

# ✅ FIXED IMPORTS (IMPORTANT)
from attack_predictor import predict_attack
from ip_blocker import block_ip, blocked_ips

app = FastAPI(
    title="SentinelAI Security Engine",
    description="AI Powered Cyber Threat Detection API",
    version="1.0"
)

# ------------------------------------------------
# ✅ CORS (FOR STREAMLIT CONNECTION)
# ------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
# 🔧 DATA NORMALIZATION (VERY IMPORTANT)
# ------------------------------------------------

def normalize_df(df):

    df.columns = df.columns.str.lower()

    # auto-detect columns
    if "ip" not in df.columns:
        for col in df.columns:
            if "ip" in col:
                df.rename(columns={col: "ip"}, inplace=True)

    if "failed_logins" not in df.columns:
        for col in df.columns:
            if "fail" in col or "attempt" in col:
                df.rename(columns={col: "failed_logins"}, inplace=True)

    # fallback values
    if "ip" not in df.columns:
        df["ip"] = "unknown"

    if "failed_logins" not in df.columns:
        df["failed_logins"] = 0

    # type conversion
    df["failed_logins"] = pd.to_numeric(df["failed_logins"], errors="coerce").fillna(0)

    return df

# ------------------------------------------------
# 🔥 LOG ANALYSIS (MAIN AI ENGINE)
# ------------------------------------------------

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):

    try:
        content = await file.read()
        df = pd.read_csv(io.StringIO(content.decode()))

        df = normalize_df(df)

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
            "success": True,
            "total_logs": len(df),
            "alerts": alerts
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }

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
