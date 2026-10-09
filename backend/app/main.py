from datetime import datetime, timezone
import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import sys
from typing import List

# Ensure parent directory is in sys.path so app.engine / app.gemini_triage work reliably
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from app.engine import LogEntry, analyze_log_entry
    from app.gemini_triage import triage_incident_with_gemini
    from app.log_parser import parse_uploaded_file
    from app.pdf_generator import generate_incident_pdf
except (ImportError, ModuleNotFoundError):
    from .engine import LogEntry, analyze_log_entry
    from .gemini_triage import triage_incident_with_gemini
    from .log_parser import parse_uploaded_file
    from .pdf_generator import generate_incident_pdf


load_dotenv()
MONGODB_URI = os.getenv("MONGODB_URI", "")
DB_NAME = os.getenv("DB_NAME", "log_sentinel_db")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

db_client = None
db = None

# Real-time WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"WebSocket connected. Active: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f"WebSocket disconnected. Active: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as err:
                print(f"Broadcast error: {err}")
                self.active_connections.remove(connection)

manager = ConnectionManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_client, db
    if MONGODB_URI and "your_" not in MONGODB_URI:
        try:
            db_client = AsyncIOMotorClient(MONGODB_URI)
            db = db_client[DB_NAME]
            print("Connected to MongoDB Atlas.")
        except Exception as e:
            print(f"MongoDB connection error: {e}")
    yield
    if db_client:
        db_client.close()

raw_allowed_origins = os.getenv(
    "ALLOWED_ORIGINS",
    "https://log-sentinel-frontend.onrender.com,http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000,http://localhost:4173,http://127.0.0.1:4173"
)
allowed_origins_set = set()
for item in raw_allowed_origins.split(","):
    clean = item.strip().rstrip("/")
    if clean:
        allowed_origins_set.add(clean)
        allowed_origins_set.add(f"{clean}/")

allowed_origins = list(allowed_origins_set)

app = FastAPI(title="Log Sentinel API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"https://.*\.onrender\.com",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    gemini_status = "configured" if GEMINI_API_KEY and "your_" not in GEMINI_API_KEY else "missing_key"
    mongo_status = "unconfigured"
    if db_client:
        try:
            await db.command("ping")
            mongo_status = "connected"
        except Exception as e:
            mongo_status = f"error: {str(e)}"
    return {"status": "online", "mongodb": mongo_status, "gemini": gemini_status}

@app.post("/api/ingest")
async def ingest_log(entry: LogEntry):
    result = analyze_log_entry(entry)
    gemini_data = None

    if result.get("is_anomaly"):
        ai_triage = triage_incident_with_gemini(result)
        if ai_triage:
            gemini_data = ai_triage.model_dump()
            result["gemini_triage"] = gemini_data
            result["mitre_id"] = gemini_data.get("mitre_technique_id", result.get("mitre_id"))

    if db is not None:
        try:
            doc = result.copy()
            if result.get("is_anomaly"):
                await db.incidents.insert_one(doc)
            else:
                await db.raw_logs.insert_one(doc)
        except Exception as err:
            print(f"Mongo insert error: {err}")

    await manager.broadcast(result)
    return {"success": True, "analysis": result}

@app.get("/api/incidents")
async def get_incidents(limit: int = 10):
    if db is None:
        return {"incidents": []}
    cursor = db.incidents.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
    incidents = await cursor.to_list(length=limit)
    return {"incidents": incidents}

@app.delete("/api/incidents")
async def clear_incidents():
    if db is not None:
        try:
            await db.incidents.delete_many({})
            await db.raw_logs.delete_many({})
        except Exception as err:
            print(f"Mongo clear error: {err}")
    return {"success": True, "message": "All incident data cleared cleanly"}

@app.post("/api/simulate")
async def simulate_redteam_scenario(payload: dict):
    scenario = payload.get("scenario", 1)
    results = []

    if scenario == 1:
        # Credential Stuffing
        ip = "198.51.100.45"
        for i in range(5):
            entry = LogEntry(
                ip=ip,
                method="POST",
                endpoint="/api/v1/auth",
                status_code=401,
                user_agent="Credential-Stuffing-Bot/2.1",
                raw_log=f"{ip} - - POST /api/v1/auth HTTP/1.1 401 128"
            )
            res = await ingest_log(entry)
            results.append(res["analysis"])
    elif scenario == 2:
        # Obfuscated SQLi
        ip = "45.146.164.2"
        sqli_endpoint = "/products?id=1%20UNION%20SELECT%20CHAR(39),CHAR(117),password%20FROM%20mysql.user--"
        entry = LogEntry(
            ip=ip,
            method="GET",
            endpoint=sqli_endpoint,
            status_code=500,
            user_agent="sqlmap/1.6.4#dev",
            raw_log=f"{ip} - - GET {sqli_endpoint} HTTP/1.1 500 2450"
        )
        res = await ingest_log(entry)
        results.append(res["analysis"])
    elif scenario == 3:
        # Multi-Stage APT
        ip = "91.240.118.4"
        stages = [
            ("GET", "/about", 200),
            ("GET", "/.env", 500),
            ("GET", "/admin.bak", 403),
            ("POST", "/admin/login", 401)
        ]
        for m, ep, st in stages:
            entry = LogEntry(
                ip=ip,
                method=m,
                endpoint=ep,
                status_code=st,
                user_agent="Mozilla/5.0 (APT29 Recon)",
                raw_log=f"{ip} - - {m} {ep} HTTP/1.1 {st} 1890"
            )
            res = await ingest_log(entry)
            results.append(res["analysis"])

    return {"success": True, "scenario": scenario, "events_generated": len(results), "analyses": results}

@app.get("/api/incidents/{incident_id}/pdf")
async def export_incident_pdf_by_id(incident_id: str):
    doc = None
    if db is not None:
        try:
            doc = await db.incidents.find_one({"incident_id": incident_id}, {"_id": 0})
        except Exception as err:
            print(f"Mongo pdf query error: {err}")

    if not doc:
        doc = {
            "incident_id": incident_id,
            "ip": "127.0.0.1",
            "method": "GET",
            "endpoint": "/api/v1/resource",
            "status_code": 401,
            "threat_type": "SECURITY_ANOMALY",
            "severity": "HIGH",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule_matched": ["Rule-based anomaly threshold triggered"]
        }

    try:
        pdf_bytes = generate_incident_pdf(doc)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=log-sentinel-{incident_id}.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {str(e)}")

@app.post("/api/export/pdf")
async def export_incident_pdf_post(incident_data: dict):
    if not incident_data:
        raise HTTPException(status_code=400, detail="No incident data provided")
    inc_id = incident_data.get("incident_id", "INC-REPORT")
    try:
        pdf_bytes = generate_incident_pdf(incident_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=log-sentinel-{inc_id}.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {str(e)}")

@app.post("/api/analyze-file")
async def analyze_log_file(file: UploadFile = File(...)):
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    contents = await file.read()
    if len(contents) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds maximum limit of 10MB")

    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    entries, valid_count, invalid_count = parse_uploaded_file(file.filename, contents, max_entries=2000)

    if not entries:
        return {
            "success": False,
            "filename": file.filename,
            "message": "No valid log entries could be parsed from the uploaded file",
            "total_parsed": 0,
            "valid_entries": 0,
            "invalid_entries": invalid_count,
            "anomalies_count": 0,
            "anomalies": []
        }

    analyses = []
    anomalies = []

    for entry in entries:
        analysis = analyze_log_entry(entry)
        if analysis.get("is_anomaly"):
            ai_triage = triage_incident_with_gemini(analysis)
            if ai_triage:
                gemini_data = ai_triage.model_dump()
                analysis["gemini_triage"] = gemini_data
                analysis["mitre_id"] = gemini_data.get("mitre_technique_id", analysis.get("mitre_id"))

            if db is not None:
                try:
                    await db.incidents.insert_one(analysis.copy())
                except Exception as err:
                    print(f"Mongo incident insert error: {err}")

            anomalies.append(analysis)
            try:
                await manager.broadcast(analysis)
            except Exception as b_err:
                print(f"WebSocket broadcast error during file analysis: {b_err}")
        else:
            if db is not None:
                try:
                    await db.raw_logs.insert_one(analysis.copy())
                except Exception as err:
                    pass

        analyses.append(analysis)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    threat_categories = set()
    for a in anomalies:
        sev = (a.get("severity") or "MEDIUM").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if a.get("threat_type"):
            threat_categories.add(a.get("threat_type"))

    return {
        "success": True,
        "filename": file.filename,
        "total_parsed": len(entries),
        "valid_entries": valid_count,
        "invalid_entries": invalid_count,
        "anomalies_count": len(anomalies),
        "anomalies": anomalies,
        "severity_summary": severity_counts,
        "threat_categories": list(threat_categories),
        "message": f"Successfully parsed {len(entries)} log entries. Detected {len(anomalies)} security anomalies."
    }



@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket exception: {e}")
        manager.disconnect(websocket)