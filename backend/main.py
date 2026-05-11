"""
Argos Dashboard API — argos-security (10.10.8.2) 에서 실행

엔드포인트 목록:
  GET  /api/scans                        — 스캔 목록
  GET  /api/scans/{scan_id}/details      — 스캔 세부 결과
  POST /api/scans/trigger                — 새 스캔 실행 (백그라운드)
  POST /api/scans/{scan_id}/pentest      — Red Team 결과 저장
  DELETE /api/scans/{scan_id}/pentest/{test_id} — Red Team 결과 삭제

  POST /api/ai1/results                  — AI 1 불변식 판단 결과 수신 (최신 스캔에 반영)
  POST /api/ai2/scenarios                — AI 2 체인 시나리오 수신 (최신 스캔에 반영)

  GET  /api/health

스토리지 전략:
  - PostgreSQL (argos_security DB) 가 가용할 때: 스캔 목록/세부 정보를 DB에서 읽고 씀
  - 런타임 JSON 파일 저장소는 사용하지 않음
"""

import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, model_validator

from scanner import (
    run_scan, ai1_to_scan_detail, ai2_to_scan_detail,
    ensure_invariants_table, fetch_invariants_list, save_invariant_def,
    fetch_scan_list_from_db,
    _fetch_db_violations_for_scan, _fetch_db_attack_chains_for_scan,
    _fetch_db_pentest_results_for_scan, _fetch_db_remediations_for_scan,
    _fetch_db_assets, _fetch_db_services, _fetch_db_evidence_events,
    _fetch_db_invariant_impact_for_scan,
    _fetch_db_scan_coverage_metrics,
    _fetch_db_asset_events,
    _fetch_db_asset_history_monthly,
    _build_mitre_mapping, _fetch_scan_mitre_tactic_map, _calc_coverage,
    _build_initial_invariants, _fetch_invariant_defs,
    _calc_severity_dist, _calc_zone_violations, _calc_type_violations,
    _save_scan_to_db, save_pentest_to_db, delete_pentest_from_db,
    HAS_PSYCOPG2,
)
from ingestion import ingest_dashboard_export


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("argos-api")

AI_LATEST_DIR = Path(os.getenv("AI_PACK_LATEST_DIR", "/opt/argos/security/ai_runtime/dashboard_api/latest"))

# ── AI Pack 최신 파일 읽기 헬퍼 ──────────────────────────────────────────────

def _ai_latest_json(name: str, default=None):
    path = AI_LATEST_DIR / name
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        log.warning("AI Pack latest JSON read failed: %s", path)
        return default


def _ai_latest_run_id() -> str | None:
    export = _ai_latest_json("dashboard-db-ingestion-export.json", {})
    return export.get("run_id") or export.get("scan_id")


def _augment_latest_detail_from_ai_pack(scan_id: str, detail: dict) -> dict:
    """최신 AI Pack 스캔인 경우 파일 기반 데이터로 detail을 보강한다."""
    if scan_id != _ai_latest_run_id():
        return detail

    ai2     = _ai_latest_json("ai2-chain-scenarios.json", {})
    mitre   = _ai_latest_json("mitre-tactic-map.json", {})
    timeline = _ai_latest_json("security-posture-timeline.json", {})

    chains = ai2.get("scenarios") if isinstance(ai2, dict) else None
    if chains:
        detail["attackChains"] = chains

    if mitre:
        detail["mitreTacticMap"] = mitre
    if timeline:
        detail["securityPostureTimeline"] = timeline

    return detail


# ── DB ingestion 상태 ────────────────────────────────────────────────────────
LAST_INGEST_STATUS: dict = {
    "status": "unknown",
    "message": "No AI Pack DB ingestion has run in this API process yet.",
}


# ── DB 기반 스캔 세부 데이터 조립 ─────────────────────────────────────────────

def _db_load_scan_detail(scan_id: str) -> Optional[dict]:
    """
    DB에서 여러 테이블을 조회해 scan_detail 형태로 조립한다.
    DB 미가용 또는 스캔 미존재 시 None 반환.
    """
    if not HAS_PSYCOPG2:
        return None
    violations    = _fetch_db_violations_for_scan(scan_id)
    attack_chains = _fetch_db_attack_chains_for_scan(scan_id)
    pentest       = _fetch_db_pentest_results_for_scan(scan_id)
    remediations  = _fetch_db_remediations_for_scan(scan_id)
    impact        = _fetch_db_invariant_impact_for_scan(scan_id)
    scan_coverage = _fetch_db_scan_coverage_metrics(scan_id)
    asset_events  = _fetch_db_asset_events()
    asset_history = _fetch_db_asset_history_monthly()
    assets        = _fetch_db_assets()
    services      = _fetch_db_services()
    evidence      = _fetch_db_evidence_events()
    inv_defs      = _fetch_invariant_defs()
    timeline      = _build_security_posture_timeline()

    # violations 가 비어있어도 스캔 자체는 존재할 수 있으므로 빈 detail 반환

    # invariants 목록 생성 후 violations 상태 병합 (위험도·상태가 "미점검"으로만 뜨는 문제 수정)
    inv_list = _build_initial_invariants(inv_defs)
    violation_map = {v["invariant_id"]: v for v in violations}
    for inv in inv_list:
        v = violation_map.get(inv["id"])
        if v:
            inv["status"]                       = v["status"]
            inv["severity"]                     = v["severity"]
            inv["confidence"]                   = v.get("confidence", 0.0)
            inv["violation_reason"]             = v.get("violation_reason")
            inv["summary"]                      = v.get("summary", "")
            inv["current_environment_testable"] = v.get("current_environment_testable", False)
            inv["testability_reason"]           = v.get("testability_reason", "")

    invariant_total = len(inv_list)
    violated_count = len([v for v in violations if v.get("status") == "violated"])
    applied_count = max(invariant_total - violated_count, 0)

    detail = {
        "summary": {
            "total_violations":        violated_count,
            "violated_invariant_count": violated_count,
            "applied_invariant_count":  applied_count,
            "invariant_total":         invariant_total,
            "critical_high":           sum(1 for v in violations if v.get("severity") in ("Critical", "High")),
            "attack_chains":           len(attack_chains),
        },
        "violations":           violations,
        "severityDistribution": _calc_severity_dist(violations),
        "zoneViolations":       _calc_zone_violations(violations),
        "typeViolations":       _calc_type_violations(violations),
        "attackChains":         attack_chains,
        "mitreMapping":         _build_mitre_mapping(violations, _fetch_scan_mitre_tactic_map(scan_id)),
        "pentestResults":       pentest,
        "invariantImpact":      impact,
        "scanCoverageMetrics":  scan_coverage,
        "coverage":             _calc_coverage(violations),
        "invariants":           inv_list,
        "assets":               assets,
        "services":             services,
        "evidenceEvents":       evidence,
        "remediations":         remediations,
        "assetEvents":          asset_events,
        "assetHistoryMonthly":  asset_history,
        "securityPostureTimeline": timeline,
    }
    return _augment_latest_detail_from_ai_pack(scan_id, detail)


def _build_security_posture_timeline() -> dict:
    """스캔별 위반 invariant_id 집합을 비교해 자산/위반 추이 타임라인을 만든다."""
    scans = fetch_scan_list_from_db()
    sorted_scans = sorted(
        [scan for scan in scans if scan.get("scan_id") and scan.get("scanned_at")],
        key=lambda scan: scan.get("scanned_at") or "",
    )
    points = []
    previous_violation_ids = set()
    for index, scan in enumerate(sorted_scans):
        scan_id = scan.get("scan_id")
        asset_count = int(scan.get("asset_count") or 0)
        previous_asset_count = int(sorted_scans[index - 1].get("asset_count") or asset_count) if index > 0 else asset_count
        violation_ids = _fetch_violated_invariant_ids(scan_id)
        if not violation_ids:
            violation_ids = set()
        new_violation_ids = sorted(violation_ids - previous_violation_ids) if index > 0 else []
        resolved_invariant_ids = sorted(previous_violation_ids - violation_ids) if index > 0 else []
        violation_count = len(violation_ids) if violation_ids else int(scan.get("total_violations") or 0)
        points.append({
            "run_id": scan_id,
            "created_at": scan.get("scanned_at"),
            "metrics": {
                "asset_count": asset_count,
                "service_count": int(scan.get("service_count") or 0),
                "total_violations": violation_count,
                "violated_invariant_count": violation_count,
                "asset_with_violation_count": int(scan.get("with_violation_count") or 0),
                "changed_asset_count": 0 if index == 0 else abs(asset_count - previous_asset_count),
                "new_violation_count": len(new_violation_ids),
                "resolved_invariant_count": len(resolved_invariant_ids),
                "ai2_chain_scenario_count": int(scan.get("attack_chains_count") or 0),
            },
            "changed_assets": [],
            "violated_invariants": sorted(violation_ids),
            "new_violations_since_previous_run": new_violation_ids,
            "resolved_invariants_since_previous_run": resolved_invariant_ids,
        })
        previous_violation_ids = violation_ids
    return {"points": points}


def _fetch_violated_invariant_ids(scan_id: str) -> set[str]:
    """특정 스캔에서 violated 상태인 invariant_id 집합을 반환한다."""
    if not scan_id:
        return set()
    return {
        item.get("invariant_id")
        for item in _fetch_db_violations_for_scan(scan_id)
        if item.get("status") == "violated" and item.get("invariant_id")
    }


# ── 통합 스캔 목록 로드 (DB 전용) ────────────────────────────────────────────

def _load_scan_list() -> list:
    return fetch_scan_list_from_db()


def _load_scan_detail(scan_id: str) -> Optional[dict]:
    return _db_load_scan_detail(scan_id)


# ── scan_item 헬퍼 ────────────────────────────────────────────────────────────

def _dedupe_scan_list(scans: list) -> list:
    seen = set()
    deduped = []
    for scan in scans:
        scan_id = scan.get("scan_id")
        if not scan_id or scan_id in seen:
            continue
        seen.add(scan_id)
        deduped.append(scan)
    return deduped


def _next_scan_id(scans: list) -> str:
    today  = datetime.utcnow().strftime("%Y%m%d")
    prefix = f"SCAN-{today}-"
    max_seq = 0
    for s in scans:
        sid = s.get("scan_id", "")
        if sid.startswith(prefix):
            try:
                seq = int(sid[len(prefix):])
                if seq > max_seq:
                    max_seq = seq
            except ValueError:
                pass
    return f"{prefix}{max_seq + 1:03d}"


# ── 빈 scan_item (flat 필드, schema.sql scans 컬럼 기준) ─────────────────────

def _empty_scan_item(scan_id: str, status: str = "running") -> dict:
    return {
        "scan_id":               scan_id,
        "snapshot_id":           None,
        "scanned_at":            datetime.utcnow().isoformat() + "Z",
        "status":                status,
        "score":                 0,
        "total_violations":      0,
        "critical_high":         0,
        "attack_chains_count":   0,
        "asset_count":           0,
        "service_count":         0,
    }


# ── 백그라운드 스캔 태스크 ────────────────────────────────────────────────────

def _do_scan(scan_id: str) -> None:
    log.info("스캔 시작: %s", scan_id)
    try:
        scan_item, _ = run_scan(scan_id)
    except Exception as e:
        log.error("스캔 실패 (%s): %s", scan_id, e)
        scan_item  = {**_empty_scan_item(scan_id, "failed")}
        if HAS_PSYCOPG2:
            _save_scan_to_db(
                scan_id=scan_id,
                scanned_at=datetime.utcnow(),
                status="failed",
            )
    log.info("스캔 완료: %s (score=%s, violations=%s)",
             scan_id, scan_item["score"], scan_item["total_violations"])


# ── FastAPI 앱 ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_invariants_table()
    # 저장된 스캔이 없으면 최초 스캔 한 번 자동 실행
    if not _load_scan_list():
        log.info("저장된 스캔 없음 — 초기 스캔 실행")
        first_id = _next_scan_id([])
        _do_scan(first_id)
    yield


app = FastAPI(title="PurpleTeam Dashboard API", version="1.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── 엔드포인트 ────────────────────────────────────────────────────────────────

@app.get("/api/scans")
def get_scans():
    """스캔 목록 반환 (최신 순). schema.sql scans 컬럼 기준 flat 형식."""
    scans   = _load_scan_list()
    deduped = _dedupe_scan_list(scans)
    return deduped


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
    # TODO: 운영 환경에서는 이 엔드포인트 앞단에서 인증/권한 체크가 필요하다.
    scans   = _load_scan_list()
    scan_id = _next_scan_id(scans)

    # DB에도 running 상태로 등록
    if HAS_PSYCOPG2:
        _save_scan_to_db(
            scan_id=scan_id,
            scanned_at=datetime.utcnow(),
            status="running",
        )

    background_tasks.add_task(_do_scan, scan_id)
    return {"scan_id": scan_id, "status": "running"}


@app.post("/api/ingest/db-ingestion", status_code=200)
def ingest_db_ingestion_export(export: dict):
    """
    AI Pack dashboard-db-ingestion-export.json 또는 내부 central_api 응답을 받아
    PostgreSQL 테이블에 upsert한다. UI는 이 export를 직접 렌더링하지 않는다.
    """
    global LAST_INGEST_STATUS
    result = ingest_dashboard_export(export)
    LAST_INGEST_STATUS = result
    if result["status"] == "failed":
        raise HTTPException(status_code=500, detail=result)
    if result["status"] == "db_unavailable":
        raise HTTPException(status_code=503, detail=result)
    return result


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
    related_invariants: list[str]         = []
    target_assets:      list[TargetAsset] = []
    overall_verdict:    str               # reproduced | partially_reproduced | not_reproduced | in_progress
    narrative:          Narrative


@app.post("/api/scans/{scan_id}/pentest", status_code=200)
def save_pentest_result(scan_id: str, result: RedTeamResult):
    """Red Team 결과를 저장한다. test_id 기준으로 upsert."""
    # DB 저장 (schema.sql GROUP 7)
    result_dict = result.model_dump()
    db_saved = False
    if HAS_PSYCOPG2:
        db_saved = save_pentest_to_db(scan_id, result_dict)

    return {
        "status": "ok" if db_saved else "db_failed",
        "test_id": result.test_id,
        "db_saved": db_saved,
    }


@app.delete("/api/scans/{scan_id}/pentest/{test_id}", status_code=200)
def delete_pentest_result(scan_id: str, test_id: str):
    """Red Team 결과를 test_id 기준으로 삭제한다."""
    db_deleted = False
    if HAS_PSYCOPG2:
        db_deleted = delete_pentest_from_db(scan_id, test_id)

    return {
        "status": "ok" if db_deleted else "not_found",
        "test_id": test_id,
        "db_deleted": db_deleted,
    }


# ── 불변식 정의 관리 ─────────────────────────────────────────────────────────────

@app.get("/api/invariants")
def get_invariants():
    return fetch_invariants_list()


class InvariantDefBody(BaseModel):
    id:               str
    description:      str
    invariant_source: str  = "fixed"
    severity:         str  = ""
    attack_phase:     str  = ""
    category:         str  = ""
    default_zone:     str  = ""
    weight:           int  = 1
    remediation:      str  = ""


@app.post("/api/invariants", status_code=201)
def create_invariant(body: InvariantDefBody):
    ok = save_invariant_def(
        body.id, body.description, body.invariant_source,
        body.severity, body.attack_phase,
        body.category, body.default_zone, body.weight,
        body.remediation,
    )
    return {"status": "ok" if ok else "db_unavailable", "id": body.id}


@app.get("/api/health")
def health():
    scans = _load_scan_list()
    return {
        "status":      "ok",
        "service":     "purpleteam-dashboard-api",
        "total_scans": len(scans),
        "postgresql": {
            "status": "connected" if HAS_PSYCOPG2 else "unavailable",
            "mode": "postgresql",
        },
        "ai_pack_ingest": LAST_INGEST_STATUS,
    }


# ── AI 1 결과 수신 ──────────────────────────────────────────────────────────────

_VALID_VIOLATION_REASONS = {
    "clear_violation", "partial_satisfaction", "not_determined",
    "evidence_missing", "log_trace_gap", "control_not_observed", "environment_not_ready",
}


class AI1Result(BaseModel):
    schema_version:               str
    result_id:                    str
    created_at:                   str
    invariant_id:                 str
    confidence:                   float
    severity:                     str
    evidence_ids:                 list[str]     = []
    asset_ids:                    list[str]     = []
    status:                       str           # applied | violated
    violation_reason:             Optional[str] = None
    summary:                      str
    reason:                       str
    current_environment_testable: bool          = False
    testability_reason:           str           = ""

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
    """AI 1 불변식 판단 결과를 수신해 최신 스캔에 반영한다."""
    scans = _load_scan_list()
    if not scans:
        raise HTTPException(status_code=404, detail="저장된 스캔이 없습니다. 먼저 스캔을 실행하세요.")

    latest_id = scans[0]["scan_id"]

    detail = _db_load_scan_detail(latest_id) or {}
    if not detail:
        detail = {
            "summary": {"total_violations": 0, "critical_high": 0, "attack_chains": 0},
            "violations": [], "invariants": [], "attackChains": [], "assets": [],
            "services": [], "evidenceEvents": [], "remediations": [],
        }

    all_results    = [r.model_dump() for r in bundle.items]
    violated_count = sum(1 for r in all_results if r["status"] == "violated")

    ai1_to_scan_detail(detail, scans[0], all_results)

    log.info("AI 1 결과 수신: scan=%s, violated=%d/%d",
             latest_id, violated_count, len(all_results))
    return {"status": "ok", "scan_id": latest_id, "violated_count": violated_count}


# ── AI 2 시나리오 수신 ──────────────────────────────────────────────────────────

class MitreStep(BaseModel):
    order:               int
    tactic:              str
    technique:           str           = ""
    step:                str
    related_invariants:  list[str]     = []
    reason:              str           = ""


class ValidationGuide(BaseModel):
    goal:               str          = ""
    steps:              list[str]    = []
    success_criteria:   list[str]    = []
    evidence_to_collect: list[str]   = []
    validation_requests: list[Any]   = []
    safety_boundary:    list[str]    = []


class ScenarioBasis(BaseModel):
    status:           str = ""
    violation_reason: str = ""
    summary:          str = ""


class AI2Scenario(BaseModel):
    schema_version:               str
    chain_scenario_id:            str
    created_at:                   str
    title:                        str
    source_bundle_id:             str                    = ""
    risk_level:                   str                    # critical | high | medium | low
    scenario_basis:               Optional[ScenarioBasis] = None
    current_environment_testable: bool                   = False
    testability_reason:           str                    = ""
    related_invariants:           list[str]              = []
    chain_steps:                  list[dict[str, Any]]   = []
    asset_threats:                 list[dict[str, Any]]   = []
    attack_chain:                 list[str]              = []
    mitre_attack_flow:            list[MitreStep]        = []
    manual_validation_guide:      Optional[ValidationGuide] = None


@app.post("/api/ai2/scenarios", status_code=200)
def receive_ai2_scenarios(scenarios: list[AI2Scenario]):
    """AI 2 체인 시나리오를 수신해 최신 스캔에 반영한다."""
    scans = _load_scan_list()
    if not scans:
        raise HTTPException(status_code=404, detail="저장된 스캔이 없습니다.")

    latest_id = scans[0]["scan_id"]
    detail    = _db_load_scan_detail(latest_id) or {}
    if not detail:
        detail = {
            "summary": {"total_violations": 0, "critical_high": 0, "attack_chains": 0},
            "violations": [], "attackChains": [], "assets": [],
            "services": [], "evidenceEvents": [], "remediations": [],
        }

    scenario_dicts = [s.model_dump() for s in scenarios]
    ai2_to_scan_detail(detail, scans[0], scenario_dicts)

    log.info("AI 2 시나리오 수신: scan=%s, scenarios=%d", latest_id, len(scenarios))
    return {"status": "ok", "scan_id": latest_id, "scenario_count": len(scenarios)}
