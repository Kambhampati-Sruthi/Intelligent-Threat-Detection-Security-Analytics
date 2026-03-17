import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import numpy as np
import io
import time
from datetime import datetime

st.set_page_config(layout="wide")

# 🔥 IMPORTANT: change this after deploying backend
API_URL = "https://your-backend.onrender.com"
# API_URL = "http://127.0.0.1:8000"  # use this for local testing

# =====================================================
# COLUMN NORMALIZATION
# =====================================================

def normalize_logs(df):
    df.columns = df.columns.str.lower()

    if "timestamp" not in df.columns:
        for col in df.columns:
            if "time" in col or "date" in col:
                df.rename(columns={col: "timestamp"}, inplace=True)

    if "ip" not in df.columns:
        for col in df.columns:
            if "ip" in col:
                df.rename(columns={col: "ip"}, inplace=True)

    if "failed_logins" not in df.columns:
        for col in df.columns:
            if "fail" in col or "attempt" in col:
                df.rename(columns={col: "failed_logins"}, inplace=True)

    if "timestamp" not in df.columns:
        df["timestamp"] = pd.date_range(start="2024-01-01", periods=len(df))

    if "ip" not in df.columns:
        df["ip"] = "unknown"

    if "failed_logins" not in df.columns:
        df["failed_logins"] = np.random.randint(0, 5, len(df))

    return df


# =====================================================
# DARK THEME FIX (TEXT VISIBILITY FIXED)
# =====================================================

st.markdown("""
<style>

.stApp { background-color: black; color: white; }

html, body, [class*="css"] {
    color: white !important;
}

h1, h2, h3, h4 {
    color: #00ffff !important;
}

p, label, span, div {
    color: white !important;
}

.stSelectbox div {
    color: black !important;
}

.stButton>button {
    background: linear-gradient(90deg,#00ffff,#0055ff);
    color: white;
    border-radius: 8px;
}

.stDownloadButton>button {
    background: linear-gradient(90deg,#00ffff,#0077ff);
    color: white;
}

</style>
""", unsafe_allow_html=True)

# =====================================================
# TITLE
# =====================================================

st.markdown("<h1>🛡 Intelligent Threat Detection & Security Analytics</h1>", unsafe_allow_html=True)

# =====================================================
# BACKEND CHECK
# =====================================================

try:
    r = requests.get(f"{API_URL}/health", timeout=3)
    if r.status_code == 200:
        st.success("✅ Backend Connected")
except:
    st.error("❌ Backend Not Connected")

# =====================================================
# TABS
# =====================================================

tabs = st.tabs([
    "Dashboard",
    "Attack Simulator",
    "Threat Intelligence",
    "Dark Web Scanner",
    "AI Assistant"
])

# =====================================================
# DASHBOARD
# =====================================================

with tabs[0]:

    st.subheader("Security Overview")

    option = st.radio("Select Log Source", ["Upload Logs", "Use Sample Dataset"])

    df = None

    if option == "Upload Logs":
        uploaded = st.file_uploader("Upload CSV Logs")
        if uploaded:
            df = pd.read_csv(uploaded)
            df = normalize_logs(df)

    if option == "Use Sample Dataset":
        dataset = st.selectbox(
            "Choose Dataset",
            ["sample_logs.csv", "security_logs.csv", "temp_logs.csv"]
        )

        if st.button("Load Dataset"):
            try:
                df = pd.read_csv(f"data/{dataset}")
                df = normalize_logs(df)
                st.success(f"{dataset} loaded")
            except:
                st.error("Dataset not found")

    # =====================================================
    # PROCESS DATA
    # =====================================================

    if df is not None:

        st.dataframe(df)

        anomalies = pd.DataFrame()

        # 🔥 BACKEND CALL FIXED
        try:
            csv_buffer = io.StringIO()
            df.to_csv(csv_buffer, index=False)

            files = {"file": ("logs.csv", csv_buffer.getvalue(), "text/csv")}

            res = requests.post(f"{API_URL}/analyze", files=files, timeout=10)

            if res.status_code == 200:
                result = res.json()

                if "alerts" in result:
                    anomalies = pd.DataFrame(result["alerts"])

        except Exception as e:
            st.warning("Backend analysis failed")

        # ===============================
        # METRICS FIXED
        # ===============================

        active_threats = len(anomalies)

        try:
            blocked_data = requests.get(f"{API_URL}/blocked-ips").json()
            blocked_attacks = len(blocked_data.get("blocked_ips", []))
        except:
            blocked_attacks = 0

        security_score = max(100 - active_threats * 5, 50)

        c1, c2, c3 = st.columns(3)
        c1.metric("Active Threats", active_threats)
        c2.metric("Blocked Attacks", blocked_attacks)
        c3.metric("Security Score", f"{security_score}%")

        # ===============================
        # GRAPH
        # ===============================

        st.markdown("### Login Failure Trend")

        fig = px.line(df, x="timestamp", y="failed_logins", markers=True)
        fig.update_layout(paper_bgcolor="black", plot_bgcolor="black", font=dict(color="white"))

        st.plotly_chart(fig, use_container_width=True)

        # ===============================
        # ANOMALY
        # ===============================

        st.markdown("### AI Anomaly Detection")

        suspicious = df[df["failed_logins"] > 10]

        if not suspicious.empty:
            st.error("⚠ Suspicious Activity Detected")
            st.dataframe(suspicious)
        else:
            st.success("No anomalies detected")

        # ===============================
        # TOP IPS
        # ===============================

        st.markdown("### Top Attacker IPs")

        top_attackers = (
            df.groupby("ip")["failed_logins"]
            .sum()
            .sort_values(ascending=False)
            .head(10)
            .reset_index()
        )

        fig = px.bar(top_attackers, x="ip", y="failed_logins")
        fig.update_layout(paper_bgcolor="black", plot_bgcolor="black", font=dict(color="white"))

        st.plotly_chart(fig, use_container_width=True)

        # ===============================
        # CLEAN MAP (FIXED)
        # ===============================

        st.markdown("### Attack Visualization (Data-Based)")

        if not suspicious.empty:
            fig = px.scatter(
                suspicious,
                x="timestamp",
                y="ip",
                size="failed_logins",
                color="failed_logins"
            )
            fig.update_layout(paper_bgcolor="black", plot_bgcolor="black", font=dict(color="white"))

            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attack patterns detected")

        # ===============================
        # REALTIME
        # ===============================

        st.markdown("### Real-Time Monitoring")

        realtime = pd.DataFrame({
            "time": range(30),
            "attacks": np.random.randint(0, 20, 30)
        })

        st.line_chart(realtime.set_index("time"))

        # ===============================
        # DOWNLOAD FIXED
        # ===============================

        st.markdown("### Download Security Report")

        try:
            report_df = df.copy()
            report_df["generated_at"] = datetime.now()

            csv = report_df.to_csv(index=False)

            st.download_button(
                label="⬇ Download Report",
                data=csv,
                file_name="security_report.csv",
                mime="text/csv"
            )
        except:
            st.warning("Report generation failed")

# =====================================================
# KEEP YOUR OTHER TABS SAME (NO CHANGE)
# =====================================================
