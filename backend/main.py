"""
Argos Dashboard API — argos-security (10.10.8.2) 에서 실행
프론트엔드에서 요구하는 두 엔드포인트:
  GET  /api/scans
  GET  /api/scans/{scan_id}/details
추가 엔드포인트:
  POST /api/scans/trigger           — 새 스캔 실행
  PUT  /api/scans/{scan_id}/pentest — 모의침투 결과 저장
  GET  /api/health
"""

import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scanner import run_scan

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("argos-api")

# ── 데이터 저장 경로 (Docker 볼륨 마운트: /data) ─────────────────────────────
DATA_DIR = Path(os.getenv("SCAN_DATA_DIR", "/data"))
SCAN_LIST_FILE   = DATA_DIR / "scans.json"
SCAN_DETAIL_DIR  = DATA_DIR / "scan_details"


def _init_storage() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SCAN_DETAIL_DIR.mkdir(parents=True, exist_ok=True)
    if not SCAN_LIST_FILE.exists():
        SCAN_LIST_FILE.write_text("[]", encoding="utf-8")


def _load_scan_list() -> list:
    try:
        return json.loads(SCAN_LIST_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save_scan_list(scans: list) -> None:
    SCAN_LIST_FILE.write_text(
        json.dumps(scans, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _load_scan_detail(scan_id: str) -> Optional[dict]:
    path = SCAN_DETAIL_DIR / f"{scan_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _save_scan_detail(scan_id: str, detail: dict) -> None:
    path = SCAN_DETAIL_DIR / f"{scan_id}.json"
    path.write_text(
        json.dumps(detail, ensure_ascii=False, indent=2), encoding="utf-8"
    )


# ── 새 스캔 번호 생성 ──────────────────────────────────────────────────────────

def _next_scan_id(scans: list) -> str:
    if not scans:
        return "SCAN-0001"
    nums = []
    for s in scans:
        try:
            nums.append(int(s["scan_id"].split("-")[1]))
        except (IndexError, ValueError):
            pass
    next_num = max(nums) + 1 if nums else 1
    return f"SCAN-{next_num:04d}"


# ── 백그라운드 스캔 태스크 ────────────────────────────────────────────────────

def _do_scan(scan_id: str) -> None:
    log.info("스캔 시작: %s", scan_id)
    try:
        scan_item, scan_detail = run_scan(scan_id)
    except Exception as e:
        log.error("스캔 실패 (%s): %s", scan_id, e)
        # 실패해도 빈 결과를 저장해 프론트가 오류 없이 동작하도록 한다
        scan_item = {
            "scan_id":    scan_id,
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "status":     "failed",
            "metrics": {
                "score": 0, "total_violations": 0,
                "critical_high": 0, "attack_chains": 0,
                "vulnerable_asset_count": 0, "patch_rate": 0,
            },
        }
        scan_detail = {
            "summary":              {"total_violations": 0, "critical_high": 0, "attack_chains": 0},
            "violations":           [],
            "severityDistribution": [],
            "zoneViolations":       [],
            "typeViolations":       [],
            "attackChains":         [],
            "mitreMapping":         [],
            "pentestResults":       [],
            "coverage":             {},
            "assets":               [],
            "assetHistory":         [],
            "assetEvents":          [],
            "assetPolicies":        [],
            "remediations":         [],
            "softwareAssets":       [],
            "credentialAssets":     [],
            "apiAssets":            [],
        }

    # 목록에 추가 (최신이 앞에 오도록)
    scans = _load_scan_list()
    scans.insert(0, scan_item)
    _save_scan_list(scans)
    _save_scan_detail(scan_id, scan_detail)
    log.info("스캔 완료: %s (score=%s, violations=%s)",
             scan_id,
             scan_item["metrics"]["score"],
             scan_item["metrics"]["total_violations"])


# ── FastAPI 앱 ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_storage()
    # 저장된 스캔이 없으면 최초 스캔 한 번 자동 실행
    if not _load_scan_list():
        log.info("저장된 스캔 없음 — 초기 스캔 실행")
        first_id = _next_scan_id([])
        _do_scan(first_id)
    yield


app = FastAPI(title="Argos Dashboard API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── 엔드포인트 ────────────────────────────────────────────────────────────────

@app.get("/api/scans")
def get_scans():
    """스캔 목록 반환 (최신 순)."""
    return _load_scan_list()


@app.get("/api/scans/{scan_id}/details")
def get_scan_details(scan_id: str):
    """특정 스캔의 세부 결과 반환."""
    detail = _load_scan_detail(scan_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"스캔을 찾을 수 없습니다: {scan_id}")
    return detail


@app.post("/api/scans/trigger", status_code=202)
def trigger_scan(background_tasks: BackgroundTasks):
    """새 스캔을 백그라운드에서 실행한다. 즉시 scan_id 를 반환한다."""
    scans   = _load_scan_list()
    scan_id = _next_scan_id(scans)

    # 진행 중 상태로 먼저 등록
    placeholder = {
        "scan_id":    scan_id,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "status":     "running",
        "metrics": {
            "score": 0, "total_violations": 0,
            "critical_high": 0, "attack_chains": 0,
            "vulnerable_asset_count": 0, "patch_rate": 0,
        },
    }
    scans.insert(0, placeholder)
    _save_scan_list(scans)

    background_tasks.add_task(_do_scan, scan_id)
    return {"scan_id": scan_id, "status": "running"}


class PentestPhase(BaseModel):
    phase:    str
    success:  bool
    detected: bool
    method:   str


class PentestResult(BaseModel):
    scenario_id: str
    chain_id:    str
    title:       str
    result:      str   # success | partial | fail
    phases:      list[PentestPhase]


@app.put("/api/scans/{scan_id}/pentest", status_code=200)
def update_pentest(scan_id: str, results: list[PentestResult]):
    """모의침투 결과를 저장한다 (프론트의 PentestSection 수동 입력 반영)."""
    detail = _load_scan_detail(scan_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"스캔을 찾을 수 없습니다: {scan_id}")
    detail["pentestResults"] = [r.model_dump() for r in results]
    _save_scan_detail(scan_id, detail)
    return {"status": "ok"}


@app.get("/api/health")
def health():
    scans = _load_scan_list()
    return {
        "status":      "ok",
        "service":     "argos-dashboard-api",
        "total_scans": len(scans),
    }
