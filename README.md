# 🛡️ Intelligent Threat Detection & Security Analytics (SentinelAI)

A complete AI-powered cybersecurity system that detects, analyzes, and visualizes cyber threats in real-time.

---

## 🚀 Live Project Links

🔗 **Frontend (Streamlit Dashboard)**
👉 https://intelligent-threat-detection-security-analytics.streamlit.app/

🔗 **Backend API (Hosted on Render)**
👉https://intelligent-threat-detection-security.onrender.com/docs

---

## 📌 What This Project Does

This project helps detect cyber attacks by analyzing login logs.

Instead of manually checking logs, our system:

* Reads log files (CSV format)
* Uses AI logic to detect suspicious activity
* Shows alerts in a dashboard
* Automatically blocks dangerous IPs

---

## 🧠 How It Works (Simple Explanation)

### Step 1: Upload Logs

User uploads a CSV file containing:

* IP address
* Failed login attempts

---

### Step 2: Backend Processing (FastAPI)

The backend:

* Reads the file
* Checks each row
* Uses a prediction function to classify activity

---

### Step 3: Threat Detection

| Failed Logins | Result           |
| ------------- | ---------------- |
| 0–3           | NORMAL           |
| 4–7           | SUSPICIOUS       |
| 8+            | HIGH RISK ATTACK |

---

### Step 4: Action Taken

* NORMAL → Ignore
* SUSPICIOUS → Alert shown
* HIGH RISK → Alert + IP blocked

---

### Step 5: Dashboard Output

User sees:

* Alerts list
* Attack severity
* Blocked IPs
* Threat intelligence

---

## 🧩 Features

* 🤖 AI-based threat detection
* 📊 Log file analysis
* 🔐 Automatic IP blocking
* 🌍 Threat intelligence feed
* 🕵 Dark web email checker
* 📡 API + Dashboard integration

---

## ⚙️ Technologies Used

### 🔹 Frontend

* Streamlit (for dashboard UI)

### 🔹 Backend

* FastAPI (API creation)
* Python

### 🔹 Data Processing

* Pandas
* NumPy

### 🔹 Deployment

* Render → Backend hosting
* Streamlit Cloud → Frontend hosting

---

## 🏗️ System Architecture

```id="arch01"
User → Upload Logs → Streamlit Dashboard
                 ↓
            FastAPI Backend
                 ↓
      Threat Detection Logic
                 ↓
     Alerts + Blocked IPs + Output
```

---

## 📂 Project Structure

Intelligent-Threat-Detection-Security-Analytics/
│
├── backend/
│   ├── __init__.py
│   ├── app.py                # Main FastAPI app
│   ├── attack_predictor.py  # Detection logic
│   ├── darkweb.py           # Dark web check
│   ├── ip_blocker.py        # IP blocking system
│   ├── model.py             # ML model (optional)
│   ├── threat_intel.py      # Threat intelligence
│   ├── requirements.txt
│   ├── Procfile             # Deployment config
│
├── data/
│   ├── sample_logs.csv
│   ├── security_logs.csv
│   ├── temp_logs.csv
│   ├── ip_locations.csv
│
├── frontend/
│   ├── dashboard.py         # Streamlit app
│
├── requirements.txt
└── README.md

---

## 🔍 API Endpoints

| Endpoint         | Method | Description      |
| ---------------- | ------ | ---------------- |
| `/`              | GET    | Check API        |
| `/analyze`       | POST   | Upload logs      |
| `/blocked-ips`   | GET    | View blocked IPs |
| `/threat-feed`   | GET    | Threat data      |
| `/darkweb-check` | GET    | Email check      |

---

## 🧪 Example API Test

```bash id="test01"
curl -X POST "http://127.0.0.1:8000/analyze" \
-F "file=@sample_logs.csv"
```

---

## 🛠️ How We Built This (Step-by-Step)

### 1️⃣ Created Backend

* Built API using FastAPI
* Added endpoints for analysis

---

### 2️⃣ Created AI Logic

* Simple rule-based prediction
* Based on failed login attempts

---

### 3️⃣ Built Frontend

* Used Streamlit for UI
* Connected to backend API

---

### 4️⃣ Added Features

* IP blocking system
* Threat feed
* Dark web checker

---

### 5️⃣ Deployment

#### 🔹 Backend Deployment (Render)

* Connected GitHub repo
* Set build command:

```bash id="cmd1"
pip install -r requirements.txt
```

* Start command:

```bash id="cmd2"
uvicorn backend.app:app --host 0.0.0.0 --port 10000
```

---

#### 🔹 Frontend Deployment (Streamlit Cloud)

* Connected GitHub repo
* Selected dashboard.py
* Deployed UI

---

## ⚠️ Issues Faced & Solutions

### ❌ ModuleNotFoundError: backend

✔ Fixed by updating start command:

```bash id="fix1"
uvicorn backend.app:app
```

---

### ❌ Docs not opening

✔ Fixed by ensuring FastAPI is running correctly

---

### ❌ Render not detecting port

✔ Used:

```bash id="fix2"
--host 0.0.0.0 --port 10000
```

---

## 🎯 Use Cases

* Cybersecurity monitoring
* Detect brute-force attacks
* Educational projects
* Real-time system protection

---

## 🔮 Future Improvements

* Real-time log streaming
* Machine learning models
* Cloud security integration
* Firewall automation

---

## ⭐ Final Note

This project shows how AI + Web + Security can be combined to build a smart threat detection system.

👉 Easy to use
👉 Scalable
👉 Practical for real-world use

---

