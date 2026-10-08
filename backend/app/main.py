import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
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
except (ImportError, ModuleNotFoundError):
    from .engine import LogEntry, analyze_log_entry
    from .gemini_triage import triage_incident_with_gemini


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

app = FastAPI(title="Log Sentinel API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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