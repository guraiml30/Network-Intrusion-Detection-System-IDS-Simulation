"""REST API for the IDS. Run: uvicorn api:app  (interactive docs at /docs)"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.netids import database
from src.netids.engine import analyze
from src.netids.rules import RULES

app = FastAPI(title="Network IDS Simulation API", version="1.0",
              description="Defensive, educational. Analyses flow records you send; touches no network.")


class FlowIn(BaseModel):
    timestamp: str
    src_ip: str = Field(max_length=45)
    dst_ip: str = Field(max_length=45)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str = Field("TCP", max_length=8)
    duration: float = Field(0, ge=0)
    bytes_out: float = Field(0, ge=0)
    bytes_in: float = Field(0, ge=0)
    packets: float = Field(1, ge=0)
    syn_count: float = Field(0, ge=0)
    rst_count: float = Field(0, ge=0)
    failed_auth: float = Field(0, ge=0)


class FlowBatch(BaseModel):
    flows: list[FlowIn] = Field(max_length=5000)
    use_ml: bool = False


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/rules")
def rules():
    return [{"id": r.id, "name": r.name, "kind": r.kind, "points": r.points, "mitre": r.mitre,
             "description": r.description} for r in RULES]


@app.post("/analyze")
def analyze_flows(batch: FlowBatch):
    try:
        res = analyze(pd.DataFrame([f.model_dump() for f in batch.flows]), batch.use_ml)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    alerts = [{k: v for k, v in a.items() if k != "evidence"} for a in res.alerts]
    return {"summary": res.summary, "alerts": alerts}


@app.get("/alerts")
def alerts(limit: int = 100):
    rows = database.fetch_alerts()[: max(1, min(limit, 500))]
    return [{k: v for k, v in r.items() if k != "evidence"} for r in rows]
