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

스토리지 전략:
  - PostgreSQL (argos_security DB) 가 가용할 때: 스캔 목록/세부 정보를 DB에서 읽고 씀
  - psycopg2 미설치 또는 DB 연결 실패 시: 파일 기반 JSON 폴백 사용
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

from scanner import (
    run_scan, ai1_to_scan_detail, ai2_to_scan_detail,
    ensure_invariants_table, fetch_invariants_list, save_invariant_def,
    fetch_scan_list_from_db,
    _fetch_db_violations_for_scan, _fetch_db_attack_chains_for_scan,
    _fetch_db_pentest_results_for_scan, _fetch_db_remediations_for_scan,
    _fetch_db_assets, _fetch_db_services, _fetch_db_evidence_events,
    _build_mitre_mapping_from_chains, _calc_coverage,
    _build_initial_invariants, _fetch_invariant_defs,
    _calc_severity_dist, _calc_zone_violations, _calc_type_violations,
    _save_scan_to_db, save_pentest_to_db,
    HAS_PSYCOPG2,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("argos-api")

# ── 파일 기반 폴백 스토리지 ────────────────────────────────────────────────────
DATA_DIR        = Path(os.getenv("SCAN_DATA_DIR", "/data"))
SCAN_LIST_FILE  = DATA_DIR / "scans.json"
SCAN_DETAIL_DIR = DATA_DIR / "scan_details"


def _init_storage() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SCAN_DETAIL_DIR.mkdir(parents=True, exist_ok=True)
    if not SCAN_LIST_FILE.exists():
        SCAN_LIST_FILE.write_text("[]", encoding="utf-8")


def _file_load_scan_list() -> list:
    try:
        return json.loads(SCAN_LIST_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _file_save_scan_list(scans: list) -> None:
    SCAN_LIST_FILE.write_text(
        json.dumps(scans, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _file_load_scan_detail(scan_id: str) -> Optional[dict]:
    path = SCAN_DETAIL_DIR / f"{scan_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _file_save_scan_detail(scan_id: str, detail: dict) -> None:
    path = SCAN_DETAIL_DIR / f"{scan_id}.json"
    path.write_text(
        json.dumps(detail, ensure_ascii=False, indent=2), encoding="utf-8"
    )


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
    assets        = _fetch_db_assets()
    services      = _fetch_db_services()
    evidence      = _fetch_db_evidence_events()
    inv_defs      = _fetch_invariant_defs()

    # violations 가 없고 파일에 있으면 DB에 아직 AI1 결과가 없는 것 → None 반환하면 파일 폴백
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

    detail = {
        "summary": {
            "total_violations": len(violations),
            "critical_high":    sum(1 for v in violations if v.get("severity") in ("Critical", "High")),
            "attack_chains":    len(attack_chains),
        },
        "violations":           violations,
        "severityDistribution": _calc_severity_dist(violations),
        "zoneViolations":       _calc_zone_violations(violations),
        "typeViolations":       _calc_type_violations(violations),
        "attackChains":         attack_chains,
        "mitreMapping":         _build_mitre_mapping_from_chains(attack_chains, violations),
        "pentestResults":       pentest,
        "coverage":             _calc_coverage(violations),
        "invariants":           inv_list,
        "assets":               assets,
        "services":             services,
        "evidenceEvents":       evidence,
        "remediations":         remediations,
        # 비활성 테이블 관련 키
        # "assetHistory":       [],  # [비활성] asset_history_monthly 테이블 미구현
        # "assetEvents":        [],  # [비활성] asset_events 테이블 미구현
        # "assetPolicies":      [],  # [비활성] invariant_impact 테이블 미구현
        # "softwareAssets":     [],  # [비활성] software_assets 테이블 미구현
        # "credentialAssets":   [],  # [비활성] credential_assets 테이블 미구현
        # "apiAssets":          [],  # [비활성] api_assets 테이블 미구현
    }
    return detail


# ── 통합 스캔 목록 로드 (DB 우선, 파일 폴백) ─────────────────────────────────

def _load_scan_list() -> list:
    if HAS_PSYCOPG2:
        db_list = fetch_scan_list_from_db()
        if db_list:
            return db_list
    return _file_load_scan_list()


def _load_scan_detail(scan_id: str) -> Optional[dict]:
    if HAS_PSYCOPG2:
        detail = _db_load_scan_detail(scan_id)
        if detail is not None:
            return detail
    return _file_load_scan_detail(scan_id)


def _save_scan_list(scans: list) -> None:
    """파일에 저장. DB 저장은 개별 scan 쓰기 함수에서 처리."""
    _file_save_scan_list(scans)


def _save_scan_detail(scan_id: str, detail: dict) -> None:
    """파일 폴백에 저장. DB 저장은 ai1/ai2 함수에서 처리."""
    _file_save_scan_detail(scan_id, detail)


# ── scan_item 헬퍼 ────────────────────────────────────────────────────────────

def _upsert_scan_item(scans: list, item: dict) -> list:
    scan_id = item.get("scan_id")
    if not scan_id:
        return scans
    updated = [item]
    updated.extend(s for s in scans if s.get("scan_id") != scan_id)
    return updated


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
        scan_item, scan_detail = run_scan(scan_id)
    except Exception as e:
        log.error("스캔 실패 (%s): %s", scan_id, e)
        scan_item  = {**_empty_scan_item(scan_id, "failed")}
        scan_detail = {
            "summary":              {"total_violations": 0, "critical_high": 0, "attack_chains": 0},
            "violations":           [],
            "invariants":           [],
            "severityDistribution": [],
            "zoneViolations":       [],
            "typeViolations":       [],
            "attackChains":         [],
            "mitreMapping":         [],
            "pentestResults":       [],
            "coverage":             {},
            "assets":               [],
            "services":             [],
            "evidenceEvents":       [],
            "remediations":         [],
        }

    scans = _file_load_scan_list()
    scans = _upsert_scan_item(scans, scan_item)
    _file_save_scan_list(scans)
    _file_save_scan_detail(scan_id, scan_detail)
    log.info("스캔 완료: %s (score=%s, violations=%s)",
             scan_id, scan_item["score"], scan_item["total_violations"])


# ── FastAPI 앱 ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_storage()
    ensure_invariants_table()
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
    """스캔 목록 반환 (최신 순). schema.sql scans 컬럼 기준 flat 형식."""
    scans   = _load_scan_list()
    deduped = _dedupe_scan_list(scans)
    if len(deduped) != len(scans) and not HAS_PSYCOPG2:
        _file_save_scan_list(deduped)
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
    scans   = _load_scan_list()
    scan_id = _next_scan_id(scans)

    placeholder = _empty_scan_item(scan_id, "running")

    # 파일 폴백에 running 상태 등록
    file_scans = _file_load_scan_list()
    file_scans = _upsert_scan_item(file_scans, placeholder)
    _file_save_scan_list(file_scans)

    # DB에도 running 상태로 등록
    if HAS_PSYCOPG2:
        _save_scan_to_db(
            scan_id=scan_id,
            scanned_at=datetime.utcnow(),
            status="running",
        )

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
    related_invariants: list[str]         = []
    target_assets:      list[TargetAsset] = []
    overall_verdict:    str               # reproduced | partially_reproduced | not_reproduced | in_progress
    narrative:          Narrative


@app.post("/api/scans/{scan_id}/pentest", status_code=200)
def save_pentest_result(scan_id: str, result: RedTeamResult):
    """Red Team 결과를 저장한다. test_id 기준으로 upsert."""
    # DB 저장 (schema.sql GROUP 7)
    result_dict = result.model_dump()
    if HAS_PSYCOPG2:
        save_pentest_to_db(scan_id, result_dict)

    # 파일 폴백 갱신
    detail = _file_load_scan_detail(scan_id)
    if detail is not None:
        results: list = detail.get("pentestResults", [])
        idx = next((i for i, r in enumerate(results) if r.get("test_id") == result.test_id), None)
        if idx is not None:
            results[idx] = result_dict
        else:
            results.append(result_dict)
        detail["pentestResults"] = results
        _file_save_scan_detail(scan_id, detail)

    return {"status": "ok", "test_id": result.test_id}


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
        "service":     "argos-dashboard-api",
        "total_scans": len(scans),
        "db_mode":     "postgresql" if HAS_PSYCOPG2 else "file_fallback",
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

    # 세부 데이터 로드 (DB 우선, 파일 폴백)
    detail = _file_load_scan_detail(latest_id) or _db_load_scan_detail(latest_id) or {}
    if not detail:
        detail = {
            "summary": {"total_violations": 0, "critical_high": 0, "attack_chains": 0},
            "violations": [], "invariants": [], "attackChains": [], "assets": [],
            "services": [], "evidenceEvents": [], "remediations": [],
        }

    all_results    = [r.model_dump() for r in bundle.items]
    violated_count = sum(1 for r in all_results if r["status"] == "violated")

    updated_detail, updated_item = ai1_to_scan_detail(detail, scans[0], all_results)

    # 파일 폴백 갱신
    file_scans = _file_load_scan_list()
    file_scans = [updated_item if s["scan_id"] == latest_id else s for s in file_scans]
    _file_save_scan_list(file_scans)
    _file_save_scan_detail(latest_id, updated_detail)

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
    detail    = _file_load_scan_detail(latest_id) or _db_load_scan_detail(latest_id) or {}
    if not detail:
        detail = {
            "summary": {"total_violations": 0, "critical_high": 0, "attack_chains": 0},
            "violations": [], "attackChains": [], "assets": [],
            "services": [], "evidenceEvents": [], "remediations": [],
        }

    scenario_dicts = [s.model_dump() for s in scenarios]
    updated_detail, updated_item = ai2_to_scan_detail(detail, scans[0], scenario_dicts)

    # 파일 폴백 갱신
    file_scans = _file_load_scan_list()
    file_scans = [updated_item if s["scan_id"] == latest_id else s for s in file_scans]
    _file_save_scan_list(file_scans)
    _file_save_scan_detail(latest_id, updated_detail)

    log.info("AI 2 시나리오 수신: scan=%s, scenarios=%d", latest_id, len(scenarios))
    return {"status": "ok", "scan_id": latest_id, "scenario_count": len(scenarios)}
