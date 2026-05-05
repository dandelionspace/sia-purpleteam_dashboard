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

def ai1_to_scan_detail(detail: dict, scan_item: dict, violated_raw: list) -> tuple:
    """
    AI 1 violated 항목(raw AI 1 형식)을 받아
    scan_detail과 scan_item(지표)을 갱신한 뒤 반환한다.
    """
    # 기존 violations 중 동일 invariant_id가 있으면 덮어쓰기, 없으면 추가
    existing = {v.get("invariant_id", v.get("id", "")): v
                for v in detail.get("violations", [])}

    for raw in violated_raw:
        enriched = enrich_violation(raw)
        inv_id   = enriched["invariant_id"]
        existing[inv_id] = enriched

    violations = list(existing.values())

    detail["violations"]           = violations
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
    scan_item["metrics"]["score"]           = score
    scan_item["metrics"]["total_violations"] = len(violations)
    scan_item["metrics"]["critical_high"]   = detail["summary"]["critical_high"]

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
