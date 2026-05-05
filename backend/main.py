"""
Argos Dashboard API — argos-security (10.10.8.2) 에서 실행

엔드포인트 목록:
  GET  /api/scans                        — 스캔 목록
  GET  /api/scans/{scan_id}/details      — 스캔 세부 결과
  POST /api/scans/trigger                — 새 스캔 실행 (백그라운드)
  POST /api/scans/{scan_id}/pentest      — Red Team 결과 저장

  POST /api/ai1/results                  — AI 1 불변식 판단 결과 수신 (최신 스캔에 반영)
  POST /api/ai2/scenarios                — AI 2 체인 시나리오 수신 (최신 스캔에 반영)

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
from pydantic import BaseModel, model_validator

from scanner import run_scan, ai1_to_scan_detail, ai2_to_scan_detail

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


class TargetAsset(BaseModel):
    asset_type: str
    asset_id:   str


class Narrative(BaseModel):
    attack_input_and_process: str = ""
    observed_result:          str = ""
    impact_assessment:        str = ""
    evidence_description:     str = ""
    additional_notes:         str = ""


class RedTeamResult(BaseModel):
    schema_version:     str = "argos-redteam-result-v3"
    scenario_id:        str
    test_id:            str
    tester:             str
    tested_at:          str
    related_invariants: list[str]       = []
    target_assets:      list[TargetAsset] = []
    overall_verdict:    str             # reproduced | partially_reproduced | not_reproduced | in_progress
    narrative:          Narrative


@app.post("/api/scans/{scan_id}/pentest", status_code=200)
def save_pentest_result(scan_id: str, result: RedTeamResult):
    """Red Team 결과를 저장한다. test_id 기준으로 upsert."""
    detail = _load_scan_detail(scan_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"스캔을 찾을 수 없습니다: {scan_id}")

    results: list = detail.get("pentestResults", [])
    result_dict   = result.model_dump()
    idx = next((i for i, r in enumerate(results) if r.get("test_id") == result.test_id), None)
    if idx is not None:
        results[idx] = result_dict
    else:
        results.append(result_dict)

    detail["pentestResults"] = results
    _save_scan_detail(scan_id, detail)
    return {"status": "ok", "test_id": result.test_id}


@app.get("/api/health")
def health():
    scans = _load_scan_list()
    return {
        "status":      "ok",
        "service":     "argos-dashboard-api",
        "total_scans": len(scans),
    }


# ── AI 1 결과 수신 ──────────────────────────────────────────────────────────────

_VALID_VIOLATION_REASONS = {
    "clear_violation", "partial_satisfaction", "not_determined",
    "evidence_missing", "log_trace_gap", "control_not_observed", "environment_not_ready",
}


class AI1Result(BaseModel):
    schema_version:             str
    result_id:                  str
    created_at:                 str
    invariant_id:               str
    confidence:                 float
    severity:                   str
    evidence_ids:               list[str]   = []
    asset_ids:                  list[str]   = []
    status:                     str         # applied | violated
    violation_reason:           Optional[str] = None
    summary:                    str
    reason:                     str
    current_environment_testable: bool      = False
    testability_reason:         str         = ""

    @model_validator(mode="after")
    def _validate_status_reason(self):
        if self.status == "applied":
            self.violation_reason = None
        elif self.status == "violated":
            if self.violation_reason is not None and self.violation_reason not in _VALID_VIOLATION_REASONS:
                raise ValueError(
                    f"violation_reason '{self.violation_reason}' 은 허용되지 않는 값입니다. "
                    f"허용값: {sorted(_VALID_VIOLATION_REASONS)}"
                )
        else:
            raise ValueError(f"status는 'applied' 또는 'violated' 이어야 합니다. 받은 값: '{self.status}'")
        return self


class AI1Bundle(BaseModel):
    schema_version: str
    bundle_id:      str
    created_at:     str
    items:          list[AI1Result]


@app.post("/api/ai1/results", status_code=200)
def receive_ai1_results(bundle: AI1Bundle):
    """
    AI 1 불변식 판단 결과를 수신해 최신 스캔에 반영한다.
    status == violated 항목만 violations 에 추가한다.
    """
    scans = _load_scan_list()
    if not scans:
        raise HTTPException(status_code=404, detail="저장된 스캔이 없습니다. 먼저 스캔을 실행하세요.")

    latest_id = scans[0]["scan_id"]
    detail    = _load_scan_detail(latest_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"스캔 세부 데이터 없음: {latest_id}")

    violated = [r.model_dump() for r in bundle.items if r.status == "violated"]
    updated_detail, updated_item = ai1_to_scan_detail(detail, scans[0], violated)

    # 스캔 목록 지표 갱신
    scans[0] = updated_item
    _save_scan_list(scans)
    _save_scan_detail(latest_id, updated_detail)

    log.info("AI 1 결과 수신: scan=%s, violated=%d/%d",
             latest_id, len(violated), len(bundle.items))
    return {"status": "ok", "scan_id": latest_id, "violated_count": len(violated)}


# ── AI 2 시나리오 수신 ──────────────────────────────────────────────────────────

class MitreStep(BaseModel):
    order:               int
    tactic:              str
    step:                str
    related_invariants:  list[str] = []
    reason:              str       = ""


class ValidationGuide(BaseModel):
    goal:               str          = ""
    steps:              list[str]    = []
    success_criteria:   list[str]    = []
    evidence_to_collect: list[str]   = []
    safety_boundary:    list[str]    = []


class ScenarioBasis(BaseModel):
    status:           str = ""
    violation_reason: str = ""
    summary:          str = ""


class AI2Scenario(BaseModel):
    schema_version:              str
    chain_scenario_id:           str
    created_at:                  str
    title:                       str
    source_bundle_id:            str         = ""
    risk_level:                  str         # critical | high | medium | low
    scenario_basis:              Optional[ScenarioBasis] = None
    current_environment_testable: bool       = False
    testability_reason:          str         = ""
    related_invariants:          list[str]   = []
    attack_chain:                list[str]   = []
    mitre_attack_flow:           list[MitreStep] = []
    manual_validation_guide:     Optional[ValidationGuide] = None


@app.post("/api/ai2/scenarios", status_code=200)
def receive_ai2_scenarios(scenarios: list[AI2Scenario]):
    """
    AI 2 체인 시나리오를 수신해 최신 스캔에 반영한다.
    """
    scans = _load_scan_list()
    if not scans:
        raise HTTPException(status_code=404, detail="저장된 스캔이 없습니다.")

    latest_id = scans[0]["scan_id"]
    detail    = _load_scan_detail(latest_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"스캔 세부 데이터 없음: {latest_id}")

    scenario_dicts = [s.model_dump() for s in scenarios]
    updated_detail, updated_item = ai2_to_scan_detail(detail, scans[0], scenario_dicts)

    scans[0] = updated_item
    _save_scan_list(scans)
    _save_scan_detail(latest_id, updated_detail)

    log.info("AI 2 시나리오 수신: scan=%s, scenarios=%d", latest_id, len(scenarios))
    return {"status": "ok", "scan_id": latest_id, "scenario_count": len(scenarios)}
