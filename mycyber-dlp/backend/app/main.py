import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.routers import alert, health, scan
from app.services.ner_model import load_ner_model


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("MyCyber DLP starting...")
    print("Loading NER model (dslim/bert-base-NER)...")
    await asyncio.to_thread(load_ner_model)
    print("NER model loaded successfully")
    yield
    print("MyCyber DLP shutting down...")


app = FastAPI(
    title="MyCyber DLP API",
    version="2.0.0",
    description="Data Loss Prevention platform with hybrid NER + regex PII detection",
    lifespan=lifespan,
)

app.include_router(health.router)
app.include_router(alert.router)
app.include_router(scan.router)


@app.get("/")
async def root():
    return {"service": "MyCyber DLP", "version": "2.0.0", "status": "running"}
