"""
스캔 실행 모듈 — AI 1/AI 2 결과 기반

수집 흐름:
  1. POST /api/ai1/results  → ai1_to_scan_detail()  → violations 갱신
  2. POST /api/ai2/scenarios → ai2_to_scan_detail() → attackChains / mitreMapping 갱신
  3. POST /api/scans/trigger → run_scan()            → PostgreSQL 자산 수집 + 초기 빈 스캔 생성
"""

import logging
import os
from datetime import datetime

try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

from invariants import (
    INVARIANT_META,
    SEVERITY_MAP,
    IP_PREFIX_TO_ZONE,
    TACTIC_NAMES,
    TACTIC_NAME_TO_ID,
    TECHNIQUE_NAMES,
    enrich_violation,
)

log = logging.getLogger("scanner")

DB_HOST = os.getenv("DB_HOST",     "10.10.4.2")
DB_PASS = os.getenv("DB_PASSWORD", "")

# ── 지표 계산 ─────────────────────────────────────────────────────────────────

_SEVERITY_COLORS = {
    "Critical": "#0C447C", "High": "#185FA5",
    "Medium":   "#378ADD", "Low":  "#85B7EB",
}
_DEDUCTIONS   = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
_PHASE_WEIGHTS = {"초기침투": 29, "내부이동": 25, "권한상승": 22, "데이터탈취": 20}
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
        z = v.get("server_zone", "기타")
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
        vid = v.get("id", v.get("invariant_id", ""))
        if vid in seen:
            continue
        seen.add(vid)
        items.append({
            "violation_id": vid,
            "description":  v.get("remediation", f"{v.get('description', '')} 조치 필요"),
            "attack_phase": v.get("attack_phase", ""),
            "priority":     v.get("priority", "1개월"),
            "done":         False,
        })
    _prio = {"즉시": 0, "1주": 1, "1개월": 2}
    items.sort(key=lambda x: _prio.get(x["priority"], 3))
    return items


def _build_mitre_mapping_from_violations(violations: list) -> list:
    """violations의 mitre_tactic/mitre_technique 필드로 MITRE 히트맵 데이터 생성."""
    tactic_tech: dict = {}
    for v in violations:
        tid  = v.get("mitre_tactic", "")
        tech = v.get("mitre_technique", "")
        if not tid:
            continue
        tactic_tech.setdefault(tid, {})\
            .setdefault(tech, {"violation_ids": [], "severity": v["severity"]})\
            ["violation_ids"].append(v.get("id", v.get("invariant_id", "")))

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
        result.append({
            "tactic_id":   tactic_id,
            "tactic_name": tactic_name,
            "techniques":  techniques,
        })
    return result


# ── DB 연결 헬퍼 ─────────────────────────────────────────────────────────────────

def _db_connect():
    return psycopg2.connect(
        host=DB_HOST, database="argos_db",
        user="argos_app", password=DB_PASS,
        connect_timeout=5,
    )


# ── 불변식 정의 DB 관리 ──────────────────────────────────────────────────────────

def ensure_invariants_table() -> None:
    """
    argos_db 에 invariants 테이블을 생성하고,
    비어 있으면 INVARIANT_META 기준 초기 데이터를 시딩한다.
    """
    if not HAS_PSYCOPG2:
        return
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS invariants (
                id               VARCHAR(30)  PRIMARY KEY,
                description      TEXT         NOT NULL,
                invariant_source VARCHAR(20)  NOT NULL DEFAULT 'fixed',
                category         VARCHAR(50),
                default_zone     VARCHAR(50),
                weight           INTEGER      DEFAULT 1,
                priority         VARCHAR(20)  DEFAULT '1개월',
                remediation      TEXT,
                created_at       TIMESTAMPTZ  DEFAULT NOW()
            )
        """)
        cur.execute("SELECT COUNT(*) FROM invariants")
        count = cur.fetchone()[0]
        if count == 0:
            for inv_id, meta in INVARIANT_META.items():
                cur.execute("""
                    INSERT INTO invariants
                        (id, description, invariant_source, category,
                         default_zone, weight, priority, remediation)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                """, (
                    inv_id,
                    meta.get("description", ""),
                    meta.get("invariant_source", "fixed"),
                    meta.get("type", ""),
                    meta.get("default_zone", ""),
                    meta.get("weight", 1),
                    meta.get("priority", "1개월"),
                    meta.get("remediation", ""),
                ))
        conn.commit()
        conn.close()
        log.info("invariants 테이블 준비 완료 (기존 %d개)", count)
    except Exception as e:
        log.warning("invariants 테이블 초기화 실패: %s", e)


def _fetch_invariant_defs() -> dict:
    """
    DB에서 불변식 정의를 {inv_id: meta_dict} 로 반환한다.
    DB 연결 실패 시 INVARIANT_META 를 그대로 반환한다.
    INVARIANT_META 에만 있는 추가 필드(mitre, attack_phase 등)는 병합 유지.
    """
    if not HAS_PSYCOPG2:
        return INVARIANT_META
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            SELECT id, description, invariant_source, category,
                   default_zone, weight, priority, remediation
            FROM invariants ORDER BY id
        """)
        rows = cur.fetchall()
        conn.close()
        if not rows:
            return INVARIANT_META
        result = {}
        for (inv_id, desc, src, cat, zone, w, pri, rem) in rows:
            base = INVARIANT_META.get(inv_id, {})
            result[inv_id] = {
                **base,
                "description":      desc,
                "invariant_source": src,
                "type":             cat or "",
                "default_zone":     zone or "",
                "weight":           w or 1,
                "priority":         pri or "1개월",
                "remediation":      rem or "",
            }
        return result
    except Exception as e:
        log.warning("invariants DB fetch 실패: %s", e)
        return INVARIANT_META


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
                       category: str, default_zone: str, weight: int,
                       priority: str, remediation: str) -> bool:
    """POST /api/invariants 용 — DB에 저장. 성공 여부 반환."""
    if not HAS_PSYCOPG2:
        return False
    try:
        conn = _db_connect()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO invariants
                (id, description, invariant_source, category,
                 default_zone, weight, priority, remediation)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                description      = EXCLUDED.description,
                invariant_source = EXCLUDED.invariant_source,
                category         = EXCLUDED.category,
                default_zone     = EXCLUDED.default_zone,
                weight           = EXCLUDED.weight,
                priority         = EXCLUDED.priority,
                remediation      = EXCLUDED.remediation
        """, (inv_id, description, invariant_source, category,
              default_zone, weight, priority, remediation))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        log.warning("invariant 저장 실패 (%s): %s", inv_id, e)
        return False


def _build_initial_invariants(inv_defs: dict = None) -> list:
    """
    불변식 정의(DB 또는 INVARIANT_META) 기준으로
    '미점검' 상태의 전체 불변식 목록을 생성한다.
    """
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


# ── PostgreSQL 자산 수집 ───────────────────────────────────────────────────────

def _fetch_db_assets() -> list:
    if not HAS_PSYCOPG2:
        return []
    try:
        conn = psycopg2.connect(
            host=DB_HOST, database="argos_db",
            user="argos_app", password=DB_PASS,
            connect_timeout=5,
        )
        cur = conn.cursor()
        cur.execute("""
            SELECT id::text, serial_number, model, firmware_version, status, registered_at
            FROM devices ORDER BY registered_at DESC LIMIT 100
        """)
        rows = cur.fetchall()
        conn.close()
        assets = []
        for idx, (did, serial, model, fw_ver, status, reg_at) in enumerate(rows, 1):
            assets.append({
                "id": f"ASSET-{serial}", "name": serial, "type": "IoT",
                "segment": "내부망", "zone": "운영", "ip": f"10.20.{idx}.1",
                "os": f"Argos FW {fw_ver or 'unknown'}", "os_age": 2,
                "online_status": "온라인" if status == "active" else "오프라인",
                "cvss_max": None,
                "patch_status": "적용완료" if status == "active" else "미적용",
                "edr": False, "av": False, "managed": True, "exposed": False,
                "privilege": "정상", "violation_ids": [],
                "last_seen": reg_at.isoformat() + "Z" if reg_at else None,
            })
        return assets
    except Exception as e:
        log.warning("DB asset fetch failed: %s", e)
        return []


# ── AI 1 결과 → scan_detail 갱신 ────────────────────────────────────────────────

def ai1_to_scan_detail(detail: dict, scan_item: dict, all_raw: list) -> tuple:
    """
    AI 1 전체 결과(applied + violated)를 받아
    scan_detail과 scan_item(지표)을 갱신한 뒤 반환한다.
    inv_defs는 DB에서 한 번만 조회해 violations와 invariants 양쪽에 사용한다.
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

    # invariants: applied + violated + 미점검, invariant_id 기준 upsert
    # detail 에 이미 있으면 유지, 없으면 DB 기준 미점검 목록으로 초기화
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
            "description":                raw.get("summary", meta.get("description", "")),
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
    detail["remediations"]         = _build_remediations(violations)
    detail["mitreMapping"]         = _build_mitre_mapping_from_violations(violations)
    detail["summary"] = {
        "total_violations": len(violations),
        "critical_high":    sum(1 for v in violations if v["severity"] in ("Critical", "High")),
        "attack_chains":    len(detail.get("attackChains", [])),
    }

    score = _calc_score(violations)
    scan_item["metrics"]["score"]            = score
    scan_item["metrics"]["total_violations"] = len(violations)
    scan_item["metrics"]["critical_high"]    = detail["summary"]["critical_high"]

    return detail, scan_item


# ── AI 2 시나리오 → scan_detail 갱신 ────────────────────────────────────────────

def ai2_to_scan_detail(detail: dict, scan_item: dict, scenarios: list) -> tuple:
    """
    AI 2 chain_scenario 목록을 받아
    scan_detail의 attackChains을 갱신하고 지표를 업데이트한다.
    mitreMapping은 violations 기반으로 이미 존재하므로 유지한다.
    """
    # chain_scenario_id 기준 upsert
    existing = {s.get("chain_scenario_id", ""): s
                for s in detail.get("attackChains", [])}
    for s in scenarios:
        cid = s.get("chain_scenario_id", "")
        if cid:
            existing[cid] = s

    detail["attackChains"] = list(existing.values())
    detail["summary"]["attack_chains"] = len(detail["attackChains"])
    scan_item["metrics"]["attack_chains"] = len(detail["attackChains"])

    return detail, scan_item


# ── 최초 스캔 실행 ─────────────────────────────────────────────────────────────

def run_scan(scan_id: str) -> tuple:
    """
    초기 빈 스캔을 생성한다.
    실제 violations/attackChains 는 AI 1/AI 2 결과 수신 시 채워진다.
    """
    scan_time = datetime.utcnow()
    assets    = _fetch_db_assets()

    scan_item = {
        "scan_id":    scan_id,
        "scanned_at": scan_time.isoformat() + "Z",
        "status":     "completed",
        "metrics": {
            "score":                  100,
            "total_violations":       0,
            "critical_high":          0,
            "attack_chains":          0,
            "vulnerable_asset_count": 0,
            "patch_rate":             round(
                len([a for a in assets if a.get("patch_status") == "적용완료"]) /
                max(len(assets), 1) * 100
            ),
        },
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
        "assetHistory":         [],
        "assetEvents":          [],
        "assetPolicies":        [],
        "remediations":         [],
        "softwareAssets":       [],
        "credentialAssets":     [],
        "apiAssets":            [],
    }

    log.info("초기 스캔 생성 완료: %s (자산 %d개)", scan_id, len(assets))
    return scan_item, scan_detail
