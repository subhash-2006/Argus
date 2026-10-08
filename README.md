# 🛡️ LOG SENTINEL
### AI-Assisted Autonomous Threat Detection & SOC Triage Engine
**Track: HN-CS-03 · Gemini & MongoDB Atlas Architecture Specification**

Log Sentinel is an enterprise-grade autonomous Security Operations Center (SOC) telemetry platform. It solves LLM token saturation, temporal amnesia, and hallucinated security fixes by combining **upstream Shannon entropy pre-filtering**, a **three-tiered dynamic memory topology over MongoDB Atlas Vector Search**, and a **dual-perspective Gemini reasoning pipeline**.

---

## 📐 Architecture & Novelty Overview

```
+------------------+     +-------------------------------+     +-----------------------------------+     +-------------------------+
|  Incoming Logs   | --> | Upstream Shannon Entropy Filter| --> | Dynamic Memory Topology (Atlas)   | --> | Dual-Perspective Gemini |
| Syslog / Nginx   |     | H(X) = - SUM P(x_i) log2 P(x_i)|     | Episodic + Semantic + Procedural  |     | Structured JSON Schema  |
+------------------+     +-------------------------------+     +-----------------------------------+     +-------------------------+
                                                                                                                      |
                                                                                                                      v
+------------------+     +-------------------------------+                                               +-------------------------+
| React SOC UI     | <-- | FastAPI WebSockets            | <-------------------------------------------- | MongoDB Change Streams  |
| Live Dashboard   |     | Instant Push Broadcast        |                                               | Atlas $vectorSearch     |
+------------------+     +-------------------------------+                                               +-------------------------+
```

---

## ⚡ Core Technical Features

### 1. Upstream Shannon Parameter Entropy Pre-Filtering
- Computes character entropy on request parameters before LLM invocation:
  $$\text{Shannon Entropy Metric: } H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
- **Normal Traffic Baseline**: $H \approx 2.5 - 3.5$
- **Base64 / Hex / SQLi Obfuscation Alert**: $H > 4.8$ (or $>4.5$)

### 2. Dynamic Memory Topology over Atlas Vector Search
- **A. Episodic Memory (Active Attack Chains)**:
  Indexes real-time attack fingerprints by entity (subnet hashes, session tokens). Cosine similarity scores decay exponentially over elapsed time:
  $$\text{Relevance} = \text{Sim}(q, m) \times e^{-\lambda(t_{\text{now}} - t_{\text{event}})}$$
- **B. Semantic Memory (Threat Intel Knowledge Base)**:
  Dense embeddings of MITRE ATT&CK tactics & techniques (`T1110`, `T1190`, `T1595`, `T1027`, `T1083`).
- **C. Procedural Memory (Playbooks & Verified Remediation)**:
  Few-shot repository of administrator-confirmed mitigation rules (`nginx_block`, `firewall` iptables commands), preventing hallucinated configurations.

### 3. Dual-Perspective Gemini Reasoning Pipeline
Enforces strict JSON schema contracts (`response_mime_type="application/json"`) producing dual-target outputs:
- **Plain-English Summary**: Non-SecOps business impact & threat intent explanation.
- **DevSecOps Script**: Ready-to-apply `iptables` drop rule & Nginx rate-limiting WAF patch.
- **MITRE Tag**: Automated compliance mapping to technique IDs.
- **Confidence Rating**: Deterministic confidence score ($0.0 - 1.0$).

### 4. Zero-Polling Reactive Pipeline via MongoDB Change Streams
Event-driven streaming pipeline pushing real-time log ingestion, anomaly analysis, and MongoDB change events straight to connected React SOC clients over WebSockets.

### 5. Integrated Red-Team Simulation Engine
- **Scenario 1: Credential Stuffing**: Injects burst 401 events targeting `/api/v1/auth`, tags `T1110`.
- **Scenario 2: Obfuscated SQLi**: Emits high-entropy hex/URL encoded `UNION SELECT` queries.
- **Scenario 3: Multi-Stage APT**: Simulates recon $\rightarrow$ honeytoken tripwires (`/.env`) $\rightarrow$ privilege escalation.

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.10+
- Node.js v18+ & npm
- MongoDB Atlas cluster or local MongoDB

### 1. Environment Setup
Copy `.env.example` to `backend/.env` and update credentials:
```bash
cp backend/.env.example backend/.env
```

Configuration in `backend/.env`:
```env
GEMINI_API_KEY=your_gemini_api_key_here
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/?appName=LogSentinel
DB_NAME=log_sentinel_db
```

### 2. Backend Installation & Server Launch
```bash
cd backend
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 3. Frontend SOC Dashboard Launch
```bash
cd frontend
npm install
npm run dev
```
Open **[http://127.0.0.1:5173](http://127.0.0.1:5173)** in your browser.

---

## 📡 API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/health` | `GET` | System health check (MongoDB, Gemini API, Uvicorn) |
| `/api/ingest` | `POST` | Ingest single `LogEntry` payload for real-time analysis |
| `/api/incidents` | `GET` | Retrieve recent security incidents from MongoDB |
| `/api/simulate` | `POST` | Run Red-Team Attack Scenarios (`{"scenario": 1\|2\|3}`) |
| `/ws/alerts` | `WebSocket` | Real-time incident streaming feed |

---

## 🧪 Running Red-Team Simulation Engine

To run the interactive Red-Team attack simulator:
```bash
cd backend
python generate_demo_logs.py
```
Or click **Scenario 1**, **Scenario 2**, or **Scenario 3** directly in the top header of the React web interface.

---

## 📂 Project Structure

```
log-sentinel/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── engine.py          # Shannon entropy & rule detection
│   │   ├── gemini_triage.py   # Dual-perspective Gemini AI pipeline
│   │   ├── memory.py          # Dynamic Memory Topology (Episodic, Semantic, Procedural)
│   │   └── main.py            # FastAPI server & WebSocket broadcast
│   ├── generate_demo_logs.py  # Red-Team attack scenario generator
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.jsx            # React SOC Dashboard
│   │   ├── index.css          # Glassmorphic cyber theme
│   │   └── main.jsx
│   ├── index.html
│   └── package.json
├── .gitignore
├── .env.example
└── README.md
```
