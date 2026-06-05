from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime

app = FastAPI(title="MyCyber DLP - Dev Stub")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5174", "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return JSONResponse({"status": "ok"})


@app.get("/api/v1/alerts/{alert_id}/file")
async def alert_file(alert_id: str):
    # Minimal stub response matching FileDetail schema used by frontend
    now = datetime.utcnow().isoformat() + "Z"
    return JSONResponse(
        {
            "scan_id": alert_id,
            "filename": f"example_{alert_id}.txt",
            "input_preview": "This is a small preview of the file contents...",
            "entities": [{"type": "EMAIL_ADDRESS", "value": "secret@example.com", "start": 10, "end": 27}],
            "created_at": now,
        }
    )
