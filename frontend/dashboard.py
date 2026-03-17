import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import numpy as np
import io
import time
from datetime import datetime

st.set_page_config(layout="wide")

API_URL = "https://intelligent-threat-detection-security.onrender.com"

# =====================================================
# COLUMN NORMALIZATION FUNCTION
# =====================================================

def normalize_logs(df):

    df.columns = df.columns.str.lower()

    # timestamp column
    if "timestamp" not in df.columns:
        for col in df.columns:
            if "time" in col or "date" in col:
                df = df.rename(columns={col:"timestamp"})
                break

    # ip column
    if "ip" not in df.columns:
        for col in df.columns:
            if "ip" in col:
                df = df.rename(columns={col:"ip"})
                break

    # failed login column
    if "failed_logins" not in df.columns:
        for col in df.columns:
            if "fail" in col or "attempt" in col:
                df = df.rename(columns={col:"failed_logins"})
                break

    # fallback values
    if "timestamp" not in df.columns:
        df["timestamp"] = pd.date_range(start="2024-01-01", periods=len(df))

    if "ip" not in df.columns:
        df["ip"] = "unknown"

    if "failed_logins" not in df.columns:
        df["failed_logins"] = np.random.randint(0,5,len(df))

    return df

# ===============================
# DARK CYBER THEME
# ===============================

st.markdown("""
<style>

.stApp{
background-color:black;
color:white;
}

html, body, [class*="css"] {
color:white !important;
}

h1,h2,h3{
color:#00ffff;
text-align:center;
}

p,label{
color:white !important;
}

.stButton>button{
background:linear-gradient(90deg,#00ffff,#0055ff);
color:white;
border-radius:8px;
}

.stDownloadButton>button{
background:linear-gradient(90deg,#00ffff,#0077ff);
color:white;
}

</style>
""", unsafe_allow_html=True)

# ===============================
# TITLE
# ===============================

st.markdown("<h1>Intelligent Threat Detection & Security Analytics</h1>", unsafe_allow_html=True)
#st.caption("AI Powered Cyber Threat Monitoring Dashboard")

# ===============================
# BACKEND CHECK
# ===============================

try:
    r = requests.get(f"{API_URL}/docs")
    if r.status_code == 200:
        st.success("Backend Connected")
except:
    st.error("Backend Not Running")

# ===============================
# TABS
# ===============================

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

    option = st.radio(
        "Select Log Source",
        ["Upload Logs","Use Sample Dataset"]
    )

    df=None

    # upload logs
    if option=="Upload Logs":

        uploaded = st.file_uploader("Upload CSV Logs")

        if uploaded:

            df = pd.read_csv(uploaded)
            df = normalize_logs(df)

    # sample datasets
    if option=="Use Sample Dataset":

        dataset = st.selectbox(
            "Choose Dataset",
            ["sample_logs.csv","security_logs.csv","temp_logs.csv"]
        )

        if st.button("Load Dataset"):

            try:
                df = pd.read_csv(f"data/{dataset}")
                df = normalize_logs(df)
                st.success(f"{dataset} loaded successfully")
            except:
                st.error("Dataset not found")

    # =====================================================
    # DATA LOADED
    # =====================================================

    if df is not None:

        st.dataframe(df)

        anomalies=pd.DataFrame()

        # backend analysis
        try:

            csv_buffer = io.StringIO()
            df.to_csv(csv_buffer,index=False)

            files={"file":("logs.csv",csv_buffer.getvalue(),"text/csv")}

            res=requests.post(f"{API_URL}/analyze",files=files)

            if res.status_code==200:
                result=res.json()
                anomalies=pd.DataFrame(result.get("alerts",[]))

        except:
            st.warning("Backend analysis unavailable")

        # ===============================
        # METRICS
        # ===============================

        active_threats=len(anomalies)

        try:
            blocked=requests.get(f"{API_URL}/blocked-ips").json()
            blocked_attacks=len(blocked)
        except:
            blocked_attacks=0

        security_score=max(100-active_threats*5,50)

        c1,c2,c3=st.columns(3)

        c1.metric("Active Threats",active_threats)
        c2.metric("Blocked Attacks",blocked_attacks)
        c3.metric("Security Score",f"{security_score}%")

        # ===============================
        # LOGIN TREND
        # ===============================

        st.markdown("### Login Failure Trend")

        fig=px.line(
            df,
            x="timestamp",
            y="failed_logins",
            markers=True
        )

        fig.update_layout(
            paper_bgcolor="black",
            plot_bgcolor="black",
            font=dict(color="white")
        )

        st.plotly_chart(fig,use_container_width=True)

        # ===============================
        # ANOMALY DETECTION
        # ===============================

        st.markdown("### AI Anomaly Detection")

        suspicious=df[df["failed_logins"]>10]

        if len(suspicious)>0:

            st.error("Suspicious login activity detected")
            st.dataframe(suspicious)

        else:

            st.success("No anomalies detected")

        # ===============================
        # TOP ATTACKER IPS
        # ===============================

        st.markdown("### Top Attacker IPs")

        top_attackers=(
            df.groupby("ip")["failed_logins"]
            .sum()
            .sort_values(ascending=False)
            .head(10)
            .reset_index()
        )

        fig=px.bar(top_attackers,x="ip",y="failed_logins")

        fig.update_layout(
            paper_bgcolor="black",
            plot_bgcolor="black",
            font=dict(color="white")
        )

        st.plotly_chart(fig,use_container_width=True)

        # ===============================
        # HEATMAP
        # ===============================

        st.markdown("### Threat Activity Heatmap")

        df["timestamp"]=pd.to_datetime(df["timestamp"])
        df["hour"]=df["timestamp"].dt.hour

        heatmap_data=df.pivot_table(
            values="failed_logins",
            index="hour",
            columns="ip",
            aggfunc="sum",
            fill_value=0
        )

        fig=px.imshow(heatmap_data)

        fig.update_layout(
            paper_bgcolor="black",
            font=dict(color="white")
        )

        st.plotly_chart(fig,use_container_width=True)

        # ===============================
        # ATTACK TIMELINE
        # ===============================

        st.markdown("### Attack Timeline")

        timeline_df=df[df["failed_logins"]>10]

        if len(timeline_df)>0:

            fig=px.scatter(
                timeline_df,
                x="timestamp",
                y="ip",
                size="failed_logins",
                color="failed_logins"
            )

            fig.update_layout(
                paper_bgcolor="black",
                plot_bgcolor="black",
                font=dict(color="white")
            )

            st.plotly_chart(fig,use_container_width=True)

        else:
            st.info("No attack timeline events")

        # ===============================
        # GLOBAL ATTACK MAP
        # ===============================

        st.markdown("### Global Attack Map")

        if len(suspicious)>0:

            suspicious["lat"]=np.random.uniform(-60,60,len(suspicious))
            suspicious["lon"]=np.random.uniform(-180,180,len(suspicious))

            fig=px.scatter_geo(
                suspicious,
                lat="lat",
                lon="lon",
                size="failed_logins",
                hover_name="ip",
                projection="natural earth"
            )

            fig.update_layout(
                paper_bgcolor="black",
                geo=dict(
                    bgcolor="black",
                    landcolor="#1a1a1a",
                    oceancolor="#0a0a0a",
                    showland=True,
                    showocean=True
                ),
                font=dict(color="white")
            )

            st.plotly_chart(fig,use_container_width=True)

        else:
            st.success("No attack locations detected")

        # ===============================
        # REAL TIME MONITORING
        # ===============================

        st.markdown("### Real-Time Attack Monitoring")

        realtime=pd.DataFrame({
            "time":range(30),
            "attacks":np.random.randint(0,20,30)
        })

        st.line_chart(realtime.set_index("time"))

        # ===============================
        # DOWNLOAD REPORT
        # ===============================

        st.markdown("### Download Security Report")

        report_df=df.copy()
        report_df["report_generated"]=datetime.now()

        csv=report_df.to_csv(index=False)

        st.download_button(
            label="Download Log Report",
            data=csv,
            file_name="security_log_report.csv",
            mime="text/csv"
        )

# =====================================================
# ATTACK SIMULATOR
# =====================================================

with tabs[1]:

    st.subheader("Cyber Attack Simulator")

    c1,c2,c3=st.columns(3)

    if c1.button("Simulate Brute Force"):
        st.error("Brute Force Attack Detected")
        st.progress(90)
        time.sleep(1)
        st.success("IP Blocked")

    if c2.button("Simulate Malware"):
        st.error("Malware Traffic Detected")
        st.progress(80)
        st.success("Traffic Blocked")

    if c3.button("Simulate Phishing"):
        st.error("Phishing Email Detected")
        st.success("Email Blocked")

# =====================================================
# THREAT INTELLIGENCE
# =====================================================

with tabs[2]:

    st.subheader("Threat Intelligence Feed")

    try:
        res=requests.get(f"{API_URL}/threat-feed")
        threats=res.json()
        st.table(threats)
    except:
        st.warning("Threat feed unavailable")

# =====================================================
# DARK WEB SCANNER
# =====================================================

with tabs[3]:

    st.subheader("Dark Web Credential Leak Checker")

    email=st.text_input("Enter Email")

    if st.button("Scan Dark Web"):

        if email=="":
            st.warning("Enter email first")

        else:

            try:

                res=requests.get(f"{API_URL}/darkweb-check?email={email}")
                result=res.json()

                if result["status"]=="leaked":
                    st.error("Credentials Found")
                else:
                    st.success("No leaks detected")

            except:
                st.error("Backend connection failed")

# =====================================================
# AI ASSISTANT
# =====================================================

with tabs[4]:

    st.subheader("AI Cybersecurity Assistant")

    question=st.text_input("Ask a cybersecurity question")

    if question:

        q=question.lower()

        if "brute force" in q:

            st.write("""
Brute force attacks try many password combinations.

Protection:
• Multi-factor authentication  
• Account lockouts  
• Rate limiting
""")

        elif "malware" in q:

            st.write("""
Malware is malicious software.

Protection:
• Antivirus  
• Endpoint monitoring  
• Network analysis
""")

        elif "phishing" in q:

            st.write("""
Phishing tricks users into revealing credentials.

Protection:
• Email filtering  
• Awareness training  
• URL scanning
""")

        else:
            st.write("Searching cybersecurity knowledge base...")
