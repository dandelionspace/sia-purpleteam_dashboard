"""
스캔 실행 모듈 — AI 1/AI 2 결과 기반

수집 흐름:
  1. POST /api/ai1/results  → ai1_to_scan_detail()  → violations 갱신
  2. POST /api/ai2/scenarios → ai2_to_scan_detail() → attackChains / mitreMapping 갱신
  3. POST /api/scans/trigger → run_scan()            → PostgreSQL 자산 수집 + 초기 빈 스캔 생성

DB 쓰기 흐름:
  - run_scan()          → scans, scan_asset_snapshot
  - ai1_to_scan_detail() → violations, violation_assets, violation_evidence, remediations, scans(update)
  - ai2_to_scan_detail() → attack_chains, attack_chain_steps, mitre_attack_flow,
                           attack_chain_invariants, validation_guide, scans(update)
  - save_pentest_to_db() → pentest_results, pentest_related_invariants, pentest_target_assets
"""

import json
import logging
import os
from datetime import datetime

try:
    import psycopg2
    import psycopg2.extras
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

from invariants import (
    SEVERITY_MAP,
    IP_PREFIX_TO_ZONE,
    TACTIC_NAMES,
    TACTIC_NAME_TO_ID,
    TECHNIQUE_NAMES,
    enrich_violation,
)

log = logging.getLogger("scanner")

DB_HOST = os.getenv("DB_HOST", "10.10.4.2")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "argos_security")
DB_USER = os.getenv("DB_USER", "argos_app")
DB_PASS = os.getenv("DB_PASSWORD", "")

# ── 지표 계산 ─────────────────────────────────────────────────────────────────

_SEVERITY_COLORS = {
    "Critical": "#0C447C", "High": "#185FA5",
    "Medium":   "#378ADD", "Low":  "#85B7EB",
}
_DEDUCTIONS   = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
_PHASE_WEIGHTS = {
    "초기침투":  29,
    "자격증명":  17,
    "권한상승":  22,
    "방어우회":  8,
    "데이터탈취": 20,
    "내부이동":  25,
}
_TYPE_COLORS   = ["#0C447C", "#185FA5", "#378ADD", "#85B7EB", "#AECDE8"]


def _calc_score(violations: list) -> int:
    total = sum(_DEDUCTIONS.get(v.get("severity", ""), 0) for v in violations)
    return max(0, 100 - total)


def _calc_severity_dist(violations: list) -> list:
    counts = {k: 0 for k in _SEVERITY_COLORS}
    for v in violations:
        if v["severity"] in counts:
            counts[v["severity"]] += 1
    return [{"name": k, "value": n, "color": _SEVERITY_COLORS[k]}
            for k, n in counts.items()]


def _calc_zone_violations(violations: list) -> list:
    zc: dict = {}
    for v in violations:
        z = v.get("server_zone", v.get("zone", "기타"))
        zc[z] = zc.get(z, 0) + 1
    return [{"zone": k, "count": n}
            for k, n in sorted(zc.items(), key=lambda x: -x[1])]


def _calc_type_violations(violations: list) -> list:
    tc: dict = {}
    for v in violations:
        t = v.get("type", "기타")
        tc[t] = tc.get(t, 0) + 1
    return [{"name": k, "value": n, "color": _TYPE_COLORS[i % len(_TYPE_COLORS)]}
            for i, (k, n) in enumerate(sorted(tc.items(), key=lambda x: -x[1]))]


def _calc_coverage(violations: list) -> dict:
    violated: dict = {p: 0 for p in _PHASE_WEIGHTS}
    for v in violations:
        p = v.get("attack_phase")
        if p in violated:
            violated[p] += v.get("weight", 0)
    result = {}
    for phase, total in _PHASE_WEIGHTS.items():
        vw = min(violated[phase], total)
        result[phase] = {
            "total_weight":    total,
            "violated_weight": vw,
            "coverage_pct":    max(0, round((1 - vw / total) * 100)),
        }
    return result


def _build_remediations(violations: list) -> list:
    seen: set = set()
    items = []
    for v in violations:
        vid = v.get("invariant_id", v.get("id", ""))
        if vid in seen:
            continue
        seen.add(vid)
        items.append({
            "invariant_id": vid,
            "description":  v.get("remediation", f"{v.get('description', '')} 조치 필요"),
            "attack_phase": v.get("attack_phase", ""),
            "priority":     v.get("priority", "1개월"),
            "done":         False,
        })
    _prio = {"즉시": 0, "1주": 1, "1개월": 2}
    items.sort(key=lambda x: _prio.get(x["priority"], 3))
    return items


def _build_mitre_mapping_from_chains(attack_chains: list, violations: list) -> list:
    """attack_chains의 mitre_attack_flow 기반으로 MITRE 매핑을 빌드한다."""
    inv_severity = {v.get("invariant_id", ""): v.get("severity", "Low") for v in violations}
    tactic_tech: dict = {}
    for chain in attack_chains:
        for flow in chain.get("mitre_attack_flow", []):
            tactic    = flow.get("tactic", "")
            technique = flow.get("technique", "")
            related   = flow.get("related_invariants", [])
            if not tactic:
                continue
            sevs = [inv_severity.get(inv, "Low") for inv in related]
            sev  = next((s for s in ["Critical", "High", "Medium", "Low"] if s in sevs), "Low")
            bucket = tactic_tech.setdefault(tactic, {}).setdefault(
                technique, {"violation_ids": [], "severity": sev}
            )
            for inv in related:
                if inv not in bucket["violation_ids"]:
                    bucket["violation_ids"].append(inv)
    result = []
    for tactic_id, tactic_name in TACTIC_NAMES.items():
        techniques = []
        for tech_id, data in tactic_tech.get(tactic_id, {}).items():
            techniques.append({
                "technique_id": tech_id,
                "name":          TECHNIQUE_NAMES.get(tech_id, tech_id),
                "severity":      data["severity"],
                "violation_ids": data["violation_ids"],
            })
        result.append({"tactic_id": tactic_id, "tactic_name": tactic_name, "techniques": techniques})
    return result


def _fetch_scan_mitre_tactic_map(scan_id: str) -> dict:
    """scan_mitre_tactic_map 테이블에서 AI Pack이 생성한 전술-불변식 매핑을 조회한다."""
    if not HAS_PSYCOPG2:
        return {}
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            SELECT tactic_id, invariant_id, mapping_basis
            FROM scan_mitre_tactic_map
            WHERE scan_id = %s
        """, (scan_id,))
        rows = cur.fetchall()
        conn.close()
        result = {}
        for (tactic_id, invariant_id, mapping_basis) in rows:
            if tactic_id not in result:
                result[tactic_id] = {"invariant_ids": [], "mapping_basis": mapping_basis or ""}
            result[tactic_id]["invariant_ids"].append(invariant_id)
        return result
    except Exception as e:
        log.warning("scan_mitre_tactic_map fetch 실패: %s", e)
        return {}


def _build_mitre_mapping(violations: list, tactic_map: dict = None) -> list:
    """violations의 mitre_tactic 필드와 scan_mitre_tactic_map을 모두 활용해 MITRE 매핑을 빌드한다."""
    inv_severity = {v.get("invariant_id", ""): v.get("severity", "Low") for v in violations}

    # violation 필드 기반 (백엔드가 mitre_tactic을 채워줄 경우)
    tactic_data: dict = {}
    for v in violations:
        tid  = v.get("mitre_tactic", "")
        tech = v.get("mitre_technique", "")
        inv_id = v.get("invariant_id", v.get("id", ""))
        if not tid or not inv_id:
            continue
        bucket = tactic_data.setdefault(tid, {"violated_invariants": [], "techniques": {}})
        if inv_id not in bucket["violated_invariants"]:
            bucket["violated_invariants"].append(inv_id)
        if tech:
            t = bucket["techniques"].setdefault(tech, {"violation_ids": [], "severity": v.get("severity", "Low")})
            if inv_id not in t["violation_ids"]:
                t["violation_ids"].append(inv_id)

    # scan_mitre_tactic_map 기반 (AI Pack이 생성한 전술-불변식 매핑)
    if tactic_map:
        for tactic_id, data in tactic_map.items():
            bucket = tactic_data.setdefault(tactic_id, {"violated_invariants": [], "techniques": {}})
            for inv_id in data.get("invariant_ids", []):
                if inv_id not in bucket["violated_invariants"]:
                    bucket["violated_invariants"].append(inv_id)

    result = []
    for tactic_id, tactic_name in TACTIC_NAMES.items():
        bucket = tactic_data.get(tactic_id, {})
        violated_invariants = bucket.get("violated_invariants", [])
        techniques = [
            {
                "technique_id": tech_id,
                "name":          TECHNIQUE_NAMES.get(tech_id, tech_id),
                "severity":      t_data["severity"],
                "violation_ids": t_data["violation_ids"],
            }
            for tech_id, t_data in bucket.get("techniques", {}).items()
        ]
        result.append({
            "tactic_id":          tactic_id,
            "tactic_name":        tactic_name,
            "violated_invariants": violated_invariants,
            "techniques":         techniques,
        })
    return result


def _build_mitre_mapping_from_violations(violations: list) -> list:
    return _build_mitre_mapping(violations, tactic_map=None)


# ── DB 연결 헬퍼 ─────────────────────────────────────────────────────────────────

def _db_connect():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        connect_timeout=5,
    )


# ── 자산 유형 레이블 변환 (schema.sql asset_type → UI 표시용) ──────────────────

_ASSET_TYPE_LABEL = {
    "server":                "서버",
    "application_audit_log": "서버",
    "auth_service":          "서버",
    "signing_service":       "서버",
    "endpoint":              "PC",
    "iot_device":            "IoT",
    "network_device":        "네트워크 장비",
}

def _asset_type_label(asset_type: str) -> str:
    return _ASSET_TYPE_LABEL.get(asset_type, asset_type)

def _zone_to_segment(zone: str) -> str:
    if zone == "dmz":
        return "DMZ"
    if zone in ("ops", "db", "dev", "deploy", "security", "management", "backup"):
        return "내부망"
    return "내부망"


# ── 불변식 정의 DB 관리 ──────────────────────────────────────────────────────────

def ensure_invariants_table() -> None:
    """invariants 테이블 존재 여부만 확인한다. 데이터는 DB에서 직접 관리."""
    if not HAS_PSYCOPG2:
        return
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM invariants")
        count = cur.fetchone()[0]
        conn.close()
        log.info("invariants 테이블 확인 완료 (%d개)", count)
    except Exception as e:
        log.warning("invariants 테이블 확인 실패: %s", e)


def _fetch_invariant_defs() -> dict:
    """DB에서 불변식 정의를 {inv_id: meta_dict} 로 반환한다."""
    if not HAS_PSYCOPG2:
        return {}
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            SELECT invariant_id, description, invariant_source, severity,
                   default_zone, category, weight, attack_phase, remediation_default
            FROM invariants ORDER BY invariant_id
        """)
        rows = cur.fetchall()
        conn.close()
        result = {}
        for (inv_id, desc, src, sev, zone, cat, w, phase, rem) in rows:
            result[inv_id] = {
                "description":      desc,
                "invariant_source": src,
                "severity":         sev or "Medium",
                "type":             cat or "",
                "default_zone":     zone or "",
                "weight":           w or 1,
                "attack_phase":     phase or "",
                "remediation":      rem or "",
            }
        return result
    except Exception as e:
        log.warning("invariants DB fetch 실패: %s", e)
        return {}


def fetch_invariants_list() -> list:
    """GET /api/invariants 용 — 정의 목록을 [{id, description, ...}] 형태로 반환."""
    defs = _fetch_invariant_defs()
    return [
        {
            "id":               inv_id,
            "description":      meta.get("description", ""),
            "invariant_source": meta.get("invariant_source", "fixed"),
            "category":         meta.get("type", ""),
            "default_zone":     meta.get("default_zone", ""),
            "weight":           meta.get("weight", 1),
            "priority":         meta.get("priority", "1개월"),
            "remediation":      meta.get("remediation", ""),
        }
        for inv_id, meta in defs.items()
    ]


def save_invariant_def(inv_id: str, description: str, invariant_source: str,
                       severity: str, attack_phase: str,
                       category: str, default_zone: str, weight: int,
                       remediation: str) -> bool:
    if not HAS_PSYCOPG2:
        return False
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO invariants
                (invariant_id, description, invariant_source, severity, attack_phase,
                 category, default_zone, weight, remediation_default)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (invariant_id) DO UPDATE SET
                description         = EXCLUDED.description,
                invariant_source    = EXCLUDED.invariant_source,
                severity            = EXCLUDED.severity,
                attack_phase        = EXCLUDED.attack_phase,
                category            = EXCLUDED.category,
                default_zone        = EXCLUDED.default_zone,
                weight              = EXCLUDED.weight,
                remediation_default = EXCLUDED.remediation_default
        """, (inv_id, description, invariant_source, severity or None, attack_phase or None,
              category, default_zone, weight, remediation))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        log.warning("invariant 저장 실패 (%s): %s", inv_id, e)
        return False


def _build_initial_invariants(inv_defs: dict = None) -> list:
    defs = inv_defs if inv_defs is not None else _fetch_invariant_defs()
    return [
        {
            "id":                         inv_id,
            "description":                meta.get("description", ""),
            "invariant_source":           meta.get("invariant_source", "fixed"),
            "severity":                   None,
            "status":                     "미점검",
            "category":                   meta.get("type", ""),
            "default_zone":               meta.get("default_zone", ""),
            "weight":                     meta.get("weight", 1),
            "priority":                   meta.get("priority", "1개월"),
            "remediation":                meta.get("remediation", ""),
            "confidence":                 0.0,
            "violation_reason":           None,
            "summary":                    "",
            "current_environment_testable": False,
            "testability_reason":         "",
        }
        for inv_id, meta in defs.items()
    ]


# ── PostgreSQL 자산 수집 (schema.sql assets 테이블 기준) ──────────────────────

def _fetch_db_assets() -> list:
    """
    assets 테이블을 조회하고 asset_related_invariants를 JOIN해 반환한다.
    schema.sql GROUP 2 기준.
    """
    if not HAS_PSYCOPG2:
        return []
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            SELECT
                a.asset_id,
                a.asset_name,
                a.asset_type,
                a.asset_category,
                a.observation_status,
                a.zone,
                a.vm,
                a.ip_hint,
                a.criticality,
                a.exposure,
                a.data_classes,
                a.observed_sources,
                a.kisa_sheets,
                a.first_seen,
                a.last_seen,
                a.record_hash,
                ARRAY_REMOVE(ARRAY_AGG(ari.invariant_id), NULL) AS related_invariant_ids
            FROM assets a
            LEFT JOIN asset_related_invariants ari ON a.asset_id = ari.asset_id
            GROUP BY a.asset_id
            ORDER BY a.last_seen DESC NULLS LAST
        """)
        rows = cur.fetchall()
        cols = [desc[0] for desc in cur.description]
        conn.close()

        assets = []
        for row in rows:
            asset = dict(zip(cols, row))
            for field in ("data_classes", "observed_sources", "kisa_sheets", "related_invariant_ids"):
                if asset[field] is None:
                    asset[field] = []
            for field in ("first_seen", "last_seen"):
                if asset[field] is not None:
                    asset[field] = asset[field].isoformat()
            # UI 호환 파생 필드
            asset["type"]    = _asset_type_label(asset.get("asset_type", ""))
            asset["segment"] = _zone_to_segment(asset.get("zone", ""))
            asset["ip"]      = asset.get("ip_hint")
            assets.append(asset)
        return assets
    except Exception as e:
        log.warning("DB assets fetch 실패: %s", e)
        return []


# ── PostgreSQL 서비스 수집 (schema.sql services 테이블 기준) ──────────────────

def _fetch_db_services() -> list:
    """
    services 테이블을 조회한다. schema.sql GROUP 2 기준.
    """
    if not HAS_PSYCOPG2:
        return []
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            SELECT
                s.service_id,
                s.name,
                s.owning_asset_id,
                s.vm,
                s.zone,
                s.component_type,
                s.deployment_ref,
                s.log_source_refs,
                s.collected_by_wazuh,
                s.observation_status,
                a.asset_name AS owning_asset_name
            FROM services s
            LEFT JOIN assets a ON s.owning_asset_id = a.asset_id
            ORDER BY s.service_id
        """)
        rows = cur.fetchall()
        cols = [desc[0] for desc in cur.description]
        conn.close()

        services = []
        for row in rows:
            svc = dict(zip(cols, row))
            # owning_asset: asset_name 우선, 없으면 asset_id
            svc["owning_asset"] = svc.pop("owning_asset_name") or svc.get("owning_asset_id", "")
            if svc.get("log_source_refs") is None:
                svc["log_source_refs"] = []
            services.append(svc)
        return services
    except Exception as e:
        log.warning("DB services fetch 실패: %s", e)
        return []


# ── PostgreSQL Evidence 수집 (schema.sql evidence_events 테이블 기준) ─────────

def _fetch_db_evidence_events(limit: int = 100) -> list:
    """
    evidence_events 파티션 테이블에서 최근 Evidence를 조회한다.
    flat 컬럼을 UI가 기대하는 nested 구조로 변환한다.
    schema.sql GROUP 4 기준.
    """
    if not HAS_PSYCOPG2:
        return []
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            SELECT
                evidence_id, timestamp, schema_version, trace_id, request_id,
                event_category, evidence_type,
                producer_vm, producer_component_id, producer_component_type,
                producer_zone, producer_asset_id, producer_service_id,
                actor_id, actor_role, actor_source_ip_class,
                token_present, token_sub, token_tenant, token_kid, token_jti,
                token_signature_valid, token_issued_by_auth_server, token_revoked,
                access_action, access_endpoint, access_method,
                access_decision, access_status_code,
                target_asset_id, target_asset_type,
                target_asset_owner_id, target_asset_tenant_id,
                control_owner_check_performed,
                control_tenant_check_performed,
                control_authz_service_used,
                raw_ref_source, raw_ref_agent, raw_ref_location, raw_ref_log_id,
                observed
            FROM evidence_events
            ORDER BY timestamp DESC
            LIMIT %s
        """, (limit,))
        rows = cur.fetchall()
        cols = [desc[0] for desc in cur.description]
        conn.close()

        events = []
        for row in rows:
            e = dict(zip(cols, row))
            if e.get("timestamp"):
                e["timestamp"] = e["timestamp"].isoformat()
            # nested 구조로 재구성 (UI 호환)
            e["producer"] = {
                "vm":             e.pop("producer_vm"),
                "component_id":   e.pop("producer_component_id"),
                "component_type": e.pop("producer_component_type"),
                "zone":           e.pop("producer_zone"),
                "asset_id":       e.pop("producer_asset_id"),
                "service_id":     e.pop("producer_service_id"),
            }
            actor_id = e.pop("actor_id", None)
            e["actor"] = {
                "actor_id":       actor_id,
                "role":           e.pop("actor_role"),
                "source_ip_class": e.pop("actor_source_ip_class"),
            } if actor_id else None
            token_present = e.pop("token_present", False)
            e["token"] = {
                "token_present":         token_present,
                "token_sub":             e.pop("token_sub"),
                "token_tenant":          e.pop("token_tenant"),
                "token_kid":             e.pop("token_kid"),
                "token_jti":             e.pop("token_jti"),
                "signature_valid":       e.pop("token_signature_valid"),
                "issued_by_auth_server": e.pop("token_issued_by_auth_server"),
                "revoked":               e.pop("token_revoked"),
            } if token_present else None
            e["access"] = {
                "action":      e.pop("access_action"),
                "endpoint":    e.pop("access_endpoint"),
                "method":      e.pop("access_method"),
                "decision":    e.pop("access_decision"),
                "status_code": e.pop("access_status_code"),
            }
            e["target"] = {
                "asset_id":  e.pop("target_asset_id"),
                "asset_type": e.pop("target_asset_type"),
                "owner_id":   e.pop("target_asset_owner_id"),
                "tenant_id":  e.pop("target_asset_tenant_id"),
            }
            e["control"] = {
                "owner_check_performed":  e.pop("control_owner_check_performed"),
                "tenant_check_performed": e.pop("control_tenant_check_performed"),
                "authz_service_used":     e.pop("control_authz_service_used"),
            }
            e["raw_ref"] = {
                "source":   e.pop("raw_ref_source"),
                "agent":    e.pop("raw_ref_agent"),
                "location": e.pop("raw_ref_location"),
                "log_id":   e.pop("raw_ref_log_id"),
            }
            events.append(e)
        return events
    except Exception as e:
        log.warning("DB evidence events fetch 실패: %s", e)
        return []


# ── PostgreSQL 스캔 자산 스냅샷 조회 (schema.sql scan_asset_snapshot) ─────────

def _fetch_db_scan_asset_snapshot(scan_id: str) -> dict:
    """scan_asset_snapshot 테이블에서 자산 집계 데이터를 조회한다."""
    if not HAS_PSYCOPG2:
        return {}
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            SELECT total, registered, unregistered, with_violation,
                   online, offline, server_count, endpoint_count, iot_count, network_count
            FROM scan_asset_snapshot
            WHERE scan_id = %s
        """, (scan_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return {}
        cols = ["total", "registered", "unregistered", "with_violation",
                "online", "offline", "server_count", "endpoint_count", "iot_count", "network_count"]
        return dict(zip(cols, row))
    except Exception as e:
        log.warning("DB scan_asset_snapshot fetch 실패 (%s): %s", scan_id, e)
        return {}


# ── PostgreSQL 스캔 저장/갱신 (schema.sql scans 테이블 기준) ─────────────────

def _save_scan_to_db(scan_id: str, scanned_at: datetime, status: str,
                     score: int = 0, total_violations: int = 0,
                     critical_high: int = 0, attack_chains_count: int = 0,
                     asset_count: int = 0, service_count: int = 0) -> None:
    """scans 테이블에 INSERT 또는 UPDATE한다. schema.sql GROUP 3 기준."""
    if not HAS_PSYCOPG2:
        return
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO scans
                (scan_id, scanned_at, status, score,
                 total_violations, critical_high, attack_chains_count,
                 asset_count, service_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (scan_id) DO UPDATE SET
                status                  = EXCLUDED.status,
                score                   = EXCLUDED.score,
                total_violations        = EXCLUDED.total_violations,
                critical_high           = EXCLUDED.critical_high,
                attack_chains_count     = EXCLUDED.attack_chains_count,
                asset_count             = EXCLUDED.asset_count,
                service_count           = EXCLUDED.service_count
        """, (scan_id, scanned_at, status, score, total_violations,
              critical_high, attack_chains_count,
              asset_count, service_count))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("scans 저장 실패 (%s): %s", scan_id, e)


def _save_scan_asset_snapshot(scan_id: str, assets: list) -> None:
    """scan_asset_snapshot 테이블에 저장한다. schema.sql GROUP 3 기준."""
    if not HAS_PSYCOPG2:
        return
    try:
        total       = len(assets)
        registered  = sum(1 for a in assets if a.get("observation_status") == "registered")
        unreg       = total - registered
        with_viol   = sum(1 for a in assets if a.get("related_invariant_ids"))
        online      = sum(1 for a in assets if a.get("online_status") == "온라인")
        offline     = total - online
        server_c    = sum(1 for a in assets if a.get("asset_category") == "server")
        endpoint_c  = sum(1 for a in assets if a.get("asset_category") == "endpoint")
        iot_c       = sum(1 for a in assets if a.get("asset_category") == "iot")
        network_c   = sum(1 for a in assets if a.get("asset_category") == "network")

        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO scan_asset_snapshot
                (scan_id, total, registered, unregistered, with_violation,
                 online, offline, server_count, endpoint_count, iot_count, network_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (scan_id) DO UPDATE SET
                total          = EXCLUDED.total,
                registered     = EXCLUDED.registered,
                unregistered   = EXCLUDED.unregistered,
                with_violation = EXCLUDED.with_violation,
                online         = EXCLUDED.online,
                offline        = EXCLUDED.offline,
                server_count   = EXCLUDED.server_count,
                endpoint_count = EXCLUDED.endpoint_count,
                iot_count      = EXCLUDED.iot_count,
                network_count  = EXCLUDED.network_count
        """, (scan_id, total, registered, unreg, with_viol,
              online, offline, server_c, endpoint_c, iot_c, network_c))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("scan_asset_snapshot 저장 실패 (%s): %s", scan_id, e)


# ── PostgreSQL violations 저장 (schema.sql GROUP 5) ──────────────────────────

def _save_violations_to_db(scan_id: str, violations: list) -> None:
    """
    violations, violation_assets, violation_evidence 테이블에 저장한다.
    schema.sql GROUP 5 기준.
    """
    if not HAS_PSYCOPG2:
        return
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        for v in violations:
            result_id   = v.get("result_id", "")
            invariant_id = v.get("invariant_id", v.get("id", ""))
            if not result_id or not invariant_id:
                continue
            cur.execute("""
                INSERT INTO violations
                    (result_id, scan_id, invariant_id, status, violation_reason,
                     summary, reason, confidence,
                     current_environment_testable, testability_reason, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (result_id) DO UPDATE SET
                    status                      = EXCLUDED.status,
                    violation_reason            = EXCLUDED.violation_reason,
                    summary                     = EXCLUDED.summary,
                    reason                      = EXCLUDED.reason,
                    confidence                  = EXCLUDED.confidence,
                    current_environment_testable= EXCLUDED.current_environment_testable,
                    testability_reason          = EXCLUDED.testability_reason
            """, (
                result_id, scan_id, invariant_id,
                v.get("status", "violated"),
                v.get("violation_reason"),
                v.get("summary", ""),
                v.get("reason", ""),
                v.get("confidence", 0.0),
                v.get("current_environment_testable", False),
                v.get("testability_reason", ""),
                v.get("created_at") or datetime.utcnow().isoformat(),
            ))
            # violation_assets (M:N)
            for asset_id in v.get("asset_ids", []):
                cur.execute("""
                    INSERT INTO violation_assets (violation_id, asset_id)
                    VALUES (%s, %s) ON CONFLICT DO NOTHING
                """, (result_id, asset_id))
            # violation_evidence (M:N)
            for evidence_id in v.get("evidence_ids", []):
                cur.execute("""
                    INSERT INTO violation_evidence (violation_id, evidence_id)
                    VALUES (%s, %s) ON CONFLICT DO NOTHING
                """, (result_id, evidence_id))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("violations DB 저장 실패: %s", e)


# ── PostgreSQL remediations 저장 (schema.sql GROUP 8) ───────────────────────

def _save_remediations_to_db(scan_id: str, remediations: list) -> None:
    """remediations 테이블에 저장한다. schema.sql GROUP 8 기준."""
    if not HAS_PSYCOPG2:
        return
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        # 이번 스캔 기존 조치항목 삭제 후 재삽입
        cur.execute("DELETE FROM remediations WHERE scan_id = %s", (scan_id,))
        for r in remediations:
            cur.execute("""
                INSERT INTO remediations
                    (invariant_id, scan_id, description, attack_phase, priority, done)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                r.get("invariant_id", ""),
                scan_id,
                r.get("description", ""),
                r.get("attack_phase", ""),
                r.get("priority", "1개월"),
                r.get("done", False),
            ))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("remediations DB 저장 실패: %s", e)


# ── PostgreSQL attack_chains 저장 (schema.sql GROUP 6) ───────────────────────

def _save_attack_chains_to_db(scan_id: str, scenarios: list) -> None:
    """
    attack_chains, attack_chain_steps, attack_chain_invariants,
    mitre_attack_flow, mitre_flow_invariants, validation_guide 테이블에 저장한다.
    schema.sql GROUP 6 기준.
    """
    if not HAS_PSYCOPG2:
        return
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        for s in scenarios:
            cid = s.get("chain_scenario_id", "")
            if not cid:
                continue
            basis = s.get("scenario_basis") or {}
            cur.execute("""
                INSERT INTO attack_chains
                    (chain_scenario_id, scan_id, created_at, title,
                     source_bundle_id, risk_level,
                     scenario_basis_status, scenario_basis_violation_reason, scenario_basis_summary,
                     current_environment_testable, testability_reason)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (chain_scenario_id) DO UPDATE SET
                    title                           = EXCLUDED.title,
                    risk_level                      = EXCLUDED.risk_level,
                    scenario_basis_status           = EXCLUDED.scenario_basis_status,
                    scenario_basis_violation_reason = EXCLUDED.scenario_basis_violation_reason,
                    scenario_basis_summary          = EXCLUDED.scenario_basis_summary,
                    current_environment_testable    = EXCLUDED.current_environment_testable,
                    testability_reason              = EXCLUDED.testability_reason
            """, (
                cid, scan_id, s.get("created_at"), s.get("title", ""),
                s.get("source_bundle_id", ""),
                s.get("risk_level", "medium"),
                basis.get("status", ""),
                basis.get("violation_reason", ""),
                basis.get("summary", ""),
                s.get("current_environment_testable", False),
                s.get("testability_reason", ""),
            ))

            # attack_chain_steps (순서 보존)
            cur.execute("DELETE FROM attack_chain_steps WHERE chain_id = %s", (cid,))
            for i, step_text in enumerate(s.get("attack_chain", []), 1):
                cur.execute("""
                    INSERT INTO attack_chain_steps (chain_id, step_order, step_text)
                    VALUES (%s, %s, %s) ON CONFLICT (chain_id, step_order) DO UPDATE
                    SET step_text = EXCLUDED.step_text
                """, (cid, i, step_text))

            # attack_chain_invariants
            cur.execute("DELETE FROM attack_chain_invariants WHERE chain_id = %s", (cid,))
            for inv_id in s.get("related_invariants", []):
                cur.execute("""
                    INSERT INTO attack_chain_invariants (chain_id, invariant_id)
                    VALUES (%s, %s) ON CONFLICT DO NOTHING
                """, (cid, inv_id))

            # mitre_attack_flow
            cur.execute("DELETE FROM mitre_attack_flow WHERE chain_id = %s", (cid,))
            for flow_item in s.get("mitre_attack_flow", []):
                cur.execute("""
                    INSERT INTO mitre_attack_flow
                        (chain_id, flow_order, tactic, technique, step, reason)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (chain_id, flow_order) DO UPDATE SET
                        tactic = EXCLUDED.tactic, technique = EXCLUDED.technique,
                        step = EXCLUDED.step, reason = EXCLUDED.reason
                    RETURNING id
                """, (
                    cid,
                    flow_item.get("order", 0),
                    flow_item.get("tactic", ""),
                    flow_item.get("technique", ""),
                    flow_item.get("step", ""),
                    flow_item.get("reason", ""),
                ))
                flow_id = cur.fetchone()
                if flow_id:
                    for inv_id in flow_item.get("related_invariants", []):
                        cur.execute("""
                            INSERT INTO mitre_flow_invariants (flow_id, invariant_id)
                            VALUES (%s, %s) ON CONFLICT DO NOTHING
                        """, (flow_id[0], inv_id))

            # validation_guide
            guide = s.get("manual_validation_guide")
            if guide:
                steps    = guide.get("steps", [])
                criteria = guide.get("success_criteria", [])
                evidence = guide.get("evidence_to_collect", [])
                boundary = guide.get("safety_boundary", [])
                cur.execute("""
                    INSERT INTO validation_guide
                        (chain_id, goal, steps, success_criteria, evidence_to_collect, safety_boundary)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (chain_id) DO UPDATE SET
                        goal               = EXCLUDED.goal,
                        steps              = EXCLUDED.steps,
                        success_criteria   = EXCLUDED.success_criteria,
                        evidence_to_collect = EXCLUDED.evidence_to_collect,
                        safety_boundary    = EXCLUDED.safety_boundary
                """, (
                    cid,
                    guide.get("goal", ""),
                    json.dumps(steps,    ensure_ascii=False),
                    json.dumps(criteria, ensure_ascii=False),
                    json.dumps(evidence, ensure_ascii=False),
                    json.dumps(boundary, ensure_ascii=False),
                ))

        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("attack_chains DB 저장 실패: %s", e)


# ── PostgreSQL pentest_results 저장 (schema.sql GROUP 7) ─────────────────────

def save_pentest_to_db(scan_id: str, result: dict) -> None:
    """
    pentest_results, pentest_related_invariants, pentest_target_assets 에 저장한다.
    schema.sql GROUP 7 기준.
    """
    if not HAS_PSYCOPG2:
        return
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        narrative = result.get("narrative", {})
        cur.execute("""
            INSERT INTO pentest_results
                (test_id, schema_version, scan_id, scenario_id, tester, tested_at,
                 overall_verdict,
                 attack_input_and_process, observed_result,
                 impact_assessment, evidence_description, additional_notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (test_id) DO UPDATE SET
                overall_verdict          = EXCLUDED.overall_verdict,
                attack_input_and_process = EXCLUDED.attack_input_and_process,
                observed_result          = EXCLUDED.observed_result,
                impact_assessment        = EXCLUDED.impact_assessment,
                evidence_description     = EXCLUDED.evidence_description,
                additional_notes         = EXCLUDED.additional_notes
        """, (
            result.get("test_id", ""),
            result.get("schema_version", "argos-redteam-result-v3"),
            scan_id,
            result.get("scenario_id"),
            result.get("tester", ""),
            result.get("tested_at"),
            result.get("overall_verdict", "in_progress"),
            narrative.get("attack_input_and_process", ""),
            narrative.get("observed_result", ""),
            narrative.get("impact_assessment", ""),
            narrative.get("evidence_description", ""),
            narrative.get("additional_notes", ""),
        ))
        # pentest_related_invariants
        cur.execute("DELETE FROM pentest_related_invariants WHERE test_id = %s",
                    (result.get("test_id", ""),))
        for inv_id in result.get("related_invariants", []):
            cur.execute("""
                INSERT INTO pentest_related_invariants (test_id, invariant_id)
                VALUES (%s, %s) ON CONFLICT DO NOTHING
            """, (result.get("test_id", ""), inv_id))
        # pentest_target_assets
        cur.execute("DELETE FROM pentest_target_assets WHERE test_id = %s",
                    (result.get("test_id", ""),))
        for ta in result.get("target_assets", []):
            cur.execute("""
                INSERT INTO pentest_target_assets (test_id, asset_id, asset_type)
                VALUES (%s, %s, %s) ON CONFLICT DO NOTHING
            """, (result.get("test_id", ""), ta.get("asset_id", ""), ta.get("asset_type", "")))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("pentest_results DB 저장 실패: %s", e)


# ── PostgreSQL 스캔 목록 조회 (schema.sql scans 테이블 기준) ─────────────────

def fetch_scan_list_from_db() -> list:
    """
    scans 테이블에서 스캔 목록을 반환한다. 최신 순 정렬.
    scan_asset_snapshot과 LEFT JOIN해 unregistered_count, with_violation_count 포함.
    """
    if not HAS_PSYCOPG2:
        return []
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            SELECT s.scan_id, s.snapshot_id, s.scanned_at, s.status,
                   s.score, s.total_violations, s.critical_high,
                   s.attack_chains_count,
                   s.asset_count, s.service_count,
                   COALESCE(sas.unregistered, 0)   AS unregistered_count,
                   COALESCE(sas.with_violation, 0)  AS with_violation_count,
                   COALESCE(sas.online, 0)           AS online_count,
                   COALESCE(sas.offline, 0)          AS offline_count
            FROM scans s
            LEFT JOIN scan_asset_snapshot sas ON s.scan_id = sas.scan_id
            ORDER BY s.scanned_at DESC
        """)
        rows = cur.fetchall()
        cols = [desc[0] for desc in cur.description]
        conn.close()
        result = []
        for row in rows:
            item = dict(zip(cols, row))
            if item.get("scanned_at"):
                item["scanned_at"] = item["scanned_at"].isoformat()
            for field in ("score", "total_violations", "critical_high",
                          "attack_chains_count",
                          "asset_count", "service_count",
                          "unregistered_count", "with_violation_count",
                          "online_count", "offline_count"):
                if item.get(field) is None:
                    item[field] = 0
            result.append(item)
        return result
    except Exception as e:
        log.warning("DB scan list fetch 실패: %s", e)
        return []


# ── PostgreSQL 스캔 세부 데이터 조회 ─────────────────────────────────────────

def _fetch_db_violations_for_scan(scan_id: str) -> list:
    """violations 테이블에서 특정 스캔의 violation 목록을 조회해 enrichment 적용."""
    if not HAS_PSYCOPG2:
        return []
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            SELECT v.result_id, v.invariant_id, v.status, v.violation_reason,
                   v.summary, v.reason, v.confidence,
                   v.current_environment_testable, v.testability_reason, v.created_at,
                   ARRAY_REMOVE(ARRAY_AGG(DISTINCT va.asset_id), NULL)   AS asset_ids,
                   ARRAY_REMOVE(ARRAY_AGG(DISTINCT ve.evidence_id), NULL) AS evidence_ids
            FROM violations v
            LEFT JOIN violation_assets   va ON v.result_id = va.violation_id
            LEFT JOIN violation_evidence ve ON v.result_id = ve.violation_id
            WHERE v.scan_id = %s
            GROUP BY v.result_id
            ORDER BY v.created_at
        """, (scan_id,))
        rows = cur.fetchall()
        cols = [desc[0] for desc in cur.description]
        conn.close()

        inv_defs = _fetch_invariant_defs()
        violations = []
        for row in rows:
            raw = dict(zip(cols, row))
            if raw.get("created_at"):
                raw["created_at"] = raw["created_at"].isoformat()
            raw["asset_ids"]    = raw.get("asset_ids", []) or []
            raw["evidence_ids"] = raw.get("evidence_ids", []) or []
            # invariant 메타데이터 보완
            inv_id = raw.get("invariant_id", "")
            meta   = inv_defs.get(inv_id, {})
            raw["severity"]         = meta.get("severity") or "Medium"
            raw["description"]      = meta.get("description", "")
            raw["server_zone"]      = meta.get("default_zone", "알 수 없음")
            raw["zone"]             = meta.get("default_zone", "")
            raw["type"]             = meta.get("type", "")
            raw["attack_phase"]     = meta.get("attack_phase", "")
            raw["mitre_tactic"]     = meta.get("mitre_tactic", "")
            raw["mitre_technique"]  = meta.get("mitre_technique", "")
            raw["weight"]           = meta.get("weight", 1)
            raw["invariant_source"] = meta.get("invariant_source", "fixed")
            raw["remediation"]      = meta.get("remediation", "")
            raw["priority"]         = meta.get("priority", "1개월")
            raw["detected_at"]      = raw.get("created_at", "")
            raw["id"]               = inv_id
            violations.append(raw)
        return violations
    except Exception as e:
        log.warning("DB violations fetch 실패: %s", e)
        return []


def _fetch_db_attack_chains_for_scan(scan_id: str) -> list:
    """attack_chains 및 관련 테이블에서 스캔의 공격 체인을 조회한다."""
    if not HAS_PSYCOPG2:
        return []
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            SELECT chain_scenario_id, created_at, title, source_bundle_id, risk_level,
                   scenario_basis_status, scenario_basis_violation_reason, scenario_basis_summary,
                   current_environment_testable, testability_reason
            FROM attack_chains
            WHERE scan_id = %s
            ORDER BY created_at
        """, (scan_id,))
        chains_raw = cur.fetchall()

        result = []
        for row in chains_raw:
            cid = row[0]
            chain = {
                "chain_scenario_id": cid,
                "created_at":        row[1].isoformat() if row[1] else None,
                "title":             row[2],
                "source_bundle_id":  row[3],
                "risk_level":        row[4],
                "scenario_basis": {
                    "status":           row[5],
                    "violation_reason": row[6],
                    "summary":          row[7],
                },
                "current_environment_testable": row[8],
                "testability_reason":           row[9],
            }

            # attack_chain steps
            cur.execute("""
                SELECT step_text FROM attack_chain_steps
                WHERE chain_id = %s ORDER BY step_order
            """, (cid,))
            chain["attack_chain"] = [r[0] for r in cur.fetchall()]

            # related invariants
            cur.execute("""
                SELECT invariant_id FROM attack_chain_invariants
                WHERE chain_id = %s
            """, (cid,))
            chain["related_invariants"] = [r[0] for r in cur.fetchall()]

            # mitre_attack_flow
            cur.execute("""
                SELECT maf.id, maf.flow_order, maf.tactic, maf.technique, maf.step, maf.reason,
                       ARRAY_REMOVE(ARRAY_AGG(mfi.invariant_id), NULL) AS related_invariants
                FROM mitre_attack_flow maf
                LEFT JOIN mitre_flow_invariants mfi ON maf.id = mfi.flow_id
                WHERE maf.chain_id = %s
                GROUP BY maf.id
                ORDER BY maf.flow_order
            """, (cid,))
            flow_rows = cur.fetchall()
            chain["mitre_attack_flow"] = [
                {
                    "order":              r[1],
                    "tactic":             r[2],
                    "technique":          r[3],
                    "step":               r[4],
                    "reason":             r[5],
                    "related_invariants": r[6] or [],
                }
                for r in flow_rows
            ]

            # validation_guide
            cur.execute("""
                SELECT goal, steps, success_criteria, evidence_to_collect, safety_boundary
                FROM validation_guide WHERE chain_id = %s
            """, (cid,))
            vg_row = cur.fetchone()
            if vg_row:
                chain["manual_validation_guide"] = {
                    "goal":                vg_row[0],
                    "steps":               vg_row[1] or [],
                    "success_criteria":    vg_row[2] or [],
                    "evidence_to_collect": vg_row[3] or [],
                    "safety_boundary":     vg_row[4] or [],
                }
            else:
                chain["manual_validation_guide"] = None

            result.append(chain)

        conn.close()
        return result
    except Exception as e:
        log.warning("DB attack_chains fetch 실패: %s", e)
        return []


def _fetch_db_pentest_results_for_scan(scan_id: str) -> list:
    """pentest_results 테이블에서 스캔의 Red Team 결과를 조회한다."""
    if not HAS_PSYCOPG2:
        return []
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            SELECT pr.test_id, pr.schema_version, pr.scenario_id,
                   pr.tester, pr.tested_at, pr.overall_verdict,
                   pr.attack_input_and_process, pr.observed_result,
                   pr.impact_assessment, pr.evidence_description, pr.additional_notes,
                   ARRAY_REMOVE(ARRAY_AGG(DISTINCT pri.invariant_id), NULL) AS related_invariants
            FROM pentest_results pr
            LEFT JOIN pentest_related_invariants pri ON pr.test_id = pri.test_id
            WHERE pr.scan_id = %s
            GROUP BY pr.test_id
            ORDER BY pr.tested_at
        """, (scan_id,))
        rows = cur.fetchall()
        cols = ["test_id", "schema_version", "scenario_id",
                "tester", "tested_at", "overall_verdict",
                "attack_input_and_process", "observed_result",
                "impact_assessment", "evidence_description", "additional_notes",
                "related_invariants"]

        # target_assets 별도 조회
        result = []
        for row in rows:
            item = dict(zip(cols, row))
            if item.get("tested_at"):
                item["tested_at"] = item["tested_at"].isoformat()
            item["related_invariants"] = item["related_invariants"] or []
            cur.execute("""
                SELECT asset_id, asset_type FROM pentest_target_assets
                WHERE test_id = %s
            """, (item["test_id"],))
            item["target_assets"] = [
                {"asset_id": r[0], "asset_type": r[1]} for r in cur.fetchall()
            ]
            item["narrative"] = {
                "attack_input_and_process": item.pop("attack_input_and_process", ""),
                "observed_result":          item.pop("observed_result", ""),
                "impact_assessment":        item.pop("impact_assessment", ""),
                "evidence_description":     item.pop("evidence_description", ""),
                "additional_notes":         item.pop("additional_notes", ""),
            }
            result.append(item)

        conn.close()
        return result
    except Exception as e:
        log.warning("DB pentest_results fetch 실패: %s", e)
        return []


def _fetch_db_remediations_for_scan(scan_id: str) -> list:
    """remediations 테이블에서 스캔의 조치 항목을 조회한다."""
    if not HAS_PSYCOPG2:
        return []
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            SELECT id, invariant_id, description, attack_phase, priority, done
            FROM remediations
            WHERE scan_id = %s
            ORDER BY
                CASE priority WHEN '즉시' THEN 0 WHEN '1주' THEN 1 WHEN '1개월' THEN 2 ELSE 3 END
        """, (scan_id,))
        rows = cur.fetchall()
        conn.close()
        return [
            {
                "id":           r[0],
                "invariant_id": r[1],
                "description":  r[2],
                "attack_phase": r[3],
                "priority":     r[4],
                "done":         r[5],
            }
            for r in rows
        ]
    except Exception as e:
        log.warning("DB remediations fetch 실패: %s", e)
        return []


# ── AI 1 결과 → scan_detail 갱신 ────────────────────────────────────────────────

def ai1_to_scan_detail(detail: dict, scan_item: dict, all_raw: list) -> tuple:
    """
    AI 1 전체 결과(applied + violated)를 받아
    scan_detail과 scan_item(지표)을 갱신하고 DB에도 저장한다.
    """
    inv_defs     = _fetch_invariant_defs()
    violated_raw = [r for r in all_raw if r.get("status") == "violated"]

    # violations: violated 항목만, invariant_id 기준 upsert
    existing_violations = {v.get("invariant_id", v.get("id", "")): v
                           for v in detail.get("violations", [])}
    for raw in violated_raw:
        enriched = enrich_violation(raw)
        existing_violations[enriched["invariant_id"]] = enriched
    violations = list(existing_violations.values())

    # invariants: applied + violated + 미점검
    existing_inv = {i.get("id", ""): i
                    for i in (detail.get("invariants") or _build_initial_invariants(inv_defs))}
    for raw in all_raw:
        inv_id = raw.get("invariant_id", "")
        if not inv_id or inv_id not in inv_defs:
            continue
        meta    = inv_defs[inv_id]
        status  = raw.get("status", "미점검")
        sev_raw = raw.get("severity", "medium")
        existing_inv[inv_id] = {
            "id":                         inv_id,
            "description":                meta.get("description", ""),
            "evaluation_status":          status,
            "invariant_source":           meta.get("invariant_source", "fixed"),
            "severity":                   SEVERITY_MAP.get(sev_raw.lower(), sev_raw.capitalize()) if status == "violated" else None,
            "status":                     status,
            "category":                   meta.get("type", ""),
            "default_zone":               meta.get("default_zone", ""),
            "weight":                     meta.get("weight", 1),
            "priority":                   meta.get("priority", "1개월"),
            "remediation":                meta.get("remediation", ""),
            "confidence":                 raw.get("confidence", 0.0),
            "violation_reason":           raw.get("violation_reason") if status == "violated" else None,
            "summary":                    raw.get("summary", ""),
            "current_environment_testable": raw.get("current_environment_testable", False),
            "testability_reason":         raw.get("testability_reason", ""),
        }

    detail["violations"]           = violations
    detail["invariants"]           = list(existing_inv.values())
    detail["severityDistribution"] = _calc_severity_dist(violations)
    detail["zoneViolations"]       = _calc_zone_violations(violations)
    detail["typeViolations"]       = _calc_type_violations(violations)
    detail["coverage"]             = _calc_coverage(violations)
    remediations                   = _build_remediations(violations)
    detail["remediations"]         = remediations
    tactic_map = _fetch_scan_mitre_tactic_map(scan_id)
    detail["mitreMapping"]         = _build_mitre_mapping(violations, tactic_map)
    detail["summary"] = {
        "total_violations": len(violations),
        "critical_high":    sum(1 for v in violations if v["severity"] in ("Critical", "High")),
        "attack_chains":    len(detail.get("attackChains", [])),
    }

    score = _calc_score(violations)
    scan_id = scan_item.get("scan_id", "")

    # scan_item 지표 갱신 (flat 필드)
    scan_item["score"]            = score
    scan_item["total_violations"] = len(violations)
    scan_item["critical_high"]    = detail["summary"]["critical_high"]

    # DB 저장
    _save_violations_to_db(scan_id, violations)
    _save_remediations_to_db(scan_id, remediations)
    _save_scan_to_db(
        scan_id=scan_id,
        scanned_at=scan_item.get("scanned_at", datetime.utcnow()),
        status=scan_item.get("status", "completed"),
        score=score,
        total_violations=len(violations),
        critical_high=detail["summary"]["critical_high"],
        attack_chains_count=len(detail.get("attackChains", [])),
        asset_count=len(detail.get("assets", [])),
        service_count=len(detail.get("services", [])),
    )

    return detail, scan_item


# ── AI 2 시나리오 → scan_detail 갱신 ────────────────────────────────────────────

def ai2_to_scan_detail(detail: dict, scan_item: dict, scenarios: list) -> tuple:
    """
    AI 2 chain_scenario 목록을 받아 scan_detail의 attackChains을 갱신하고
    DB에도 저장한다.
    """
    existing = {s.get("chain_scenario_id", ""): s
                for s in detail.get("attackChains", [])}
    for s in scenarios:
        cid = s.get("chain_scenario_id", "")
        if cid:
            existing[cid] = s

    detail["attackChains"] = list(existing.values())
    detail["summary"]["attack_chains"] = len(detail["attackChains"])

    scan_id = scan_item.get("scan_id", "")
    scan_item["attack_chains_count"] = len(detail["attackChains"])

    # DB 저장
    _save_attack_chains_to_db(scan_id, scenarios)
    _save_scan_to_db(
        scan_id=scan_id,
        scanned_at=scan_item.get("scanned_at", datetime.utcnow()),
        status=scan_item.get("status", "completed"),
        score=scan_item.get("score", 100),
        total_violations=scan_item.get("total_violations", 0),
        critical_high=scan_item.get("critical_high", 0),
        attack_chains_count=len(detail["attackChains"]),
        asset_count=len(detail.get("assets", [])),
        service_count=len(detail.get("services", [])),
    )

    return detail, scan_item


# ── 최초 스캔 실행 ─────────────────────────────────────────────────────────────

def run_scan(scan_id: str) -> tuple:
    """
    초기 빈 스캔을 생성하고 DB에 저장한다.
    assets / services / evidence_events 를 DB에서 수집한다.
    실제 violations / attackChains 는 AI 1/AI 2 결과 수신 시 채워진다.
    """
    scan_time = datetime.utcnow()
    assets         = _fetch_db_assets()
    services       = _fetch_db_services()
    evidence_events = _fetch_db_evidence_events()

    # scans 테이블에 저장
    _save_scan_to_db(
        scan_id=scan_id,
        scanned_at=scan_time,
        status="completed",
        score=100,
        total_violations=0,
        critical_high=0,
        attack_chains_count=0,
        asset_count=len(assets),
        service_count=len(services),
    )
    # scan_asset_snapshot 저장
    _save_scan_asset_snapshot(scan_id, assets)

    scan_item = {
        "scan_id":              scan_id,
        "snapshot_id":          None,
        "scanned_at":           scan_time.isoformat() + "Z",
        "status":               "completed",
        "score":                100,
        "total_violations":     0,
        "critical_high":        0,
        "attack_chains_count":  0,
        "asset_count":          len(assets),
        "service_count":        len(services),
    }

    scan_detail = {
        "summary":              {"total_violations": 0, "critical_high": 0, "attack_chains": 0},
        "violations":           [],
        "severityDistribution": [],
        "zoneViolations":       [],
        "typeViolations":       [],
        "attackChains":         [],
        "mitreMapping":         _build_mitre_mapping_from_violations([]),
        "pentestResults":       [],
        "coverage":             _calc_coverage([]),
        "invariants":           _build_initial_invariants(),
        "assets":               assets,
        "services":             services,
        "evidenceEvents":       evidence_events,
        "remediations":         [],
        # 비활성 테이블 관련 키는 빈 배열로 유지 (UI 구조 유지)
        # "assetHistory":       [],  # [비활성] asset_history_monthly 테이블 미구현
        # "assetEvents":        [],  # [비활성] asset_events 테이블 미구현
        # "assetPolicies":      [],  # [비활성] invariant_impact 테이블 미구현
        # "softwareAssets":     [],  # [비활성] software_assets 테이블 미구현
        # "credentialAssets":   [],  # [비활성] credential_assets 테이블 미구현
        # "apiAssets":          [],  # [비활성] api_assets 테이블 미구현
    }

    log.info("초기 스캔 생성 완료: %s (자산 %d개, 서비스 %d개, evidence %d개)",
             scan_id, len(assets), len(services), len(evidence_events))
    return scan_item, scan_detail
