"""
스캔 실행 모듈
Wazuh API, PostgreSQL, MinIO 에서 데이터를 수집해 프론트 형식으로 변환한다.
"""

import os
import logging
import requests
import urllib3
from datetime import datetime, timedelta

try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

from invariants import (
    RULE_TO_INVARIANT,
    IP_PREFIX_TO_ZONE,
    TACTIC_NAMES,
    TECHNIQUE_NAMES,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("scanner")

WAZUH_API   = os.getenv("WAZUH_API",          "https://wazuh.manager:55000")
WAZUH_USER  = os.getenv("WAZUH_USER",         "wazuh-wui")
WAZUH_PASS  = os.getenv("WAZUH_API_PASSWORD", "")
DB_HOST     = os.getenv("DB_HOST",            "10.10.4.2")
DB_PASS     = os.getenv("DB_PASSWORD",        "")
MINIO_ENDPOINT  = os.getenv("MINIO_ENDPOINT",  "10.10.4.2:9000")
MINIO_SECRET    = os.getenv("MINIO_SECRET_KEY", "")

# ── Wazuh ─────────────────────────────────────────────────────────────────────

def _wazuh_token() -> str:
    resp = requests.post(
        f"{WAZUH_API}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["data"]["token"]


def fetch_wazuh_alerts(hours: int = 48) -> list:
    try:
        token = _wazuh_token()
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(
            f"{WAZUH_API}/alerts",
            headers=headers,
            params={
                "limit": 1000,
                "q": "rule.id>=100001;rule.id<=100108",
                "sort": "-timestamp",
            },
            verify=False,
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("affected_items", [])
    except Exception as e:
        log.warning("Wazuh alert fetch failed: %s", e)
    return []


# ── Wazuh alerts → violations ─────────────────────────────────────────────────

def _ip_to_zone(ip: str) -> str:
    prefix = ".".join(ip.split(".")[:3]) if ip else ""
    return IP_PREFIX_TO_ZONE.get(prefix, "")


def alerts_to_violations(alerts: list, scan_time: datetime) -> list:
    violations = []
    seen_rule_ids: set = set()

    for alert in alerts:
        try:
            rule_id = int(alert.get("rule", {}).get("id", 0))
        except (ValueError, TypeError):
            continue

        inv_def = RULE_TO_INVARIANT.get(rule_id)
        if not inv_def or rule_id in seen_rule_ids:
            continue
        seen_rule_ids.add(rule_id)

        agent_ip = alert.get("agent", {}).get("ip", "")
        zone = _ip_to_zone(agent_ip) or inv_def["default_zone"]
        timestamp = alert.get("timestamp", scan_time.isoformat() + "Z")

        violations.append({
            "id":               inv_def["id"],
            "severity":         inv_def["severity"],
            "description":      inv_def["description"],
            "server_zone":      zone,
            "type":             inv_def["type"],
            "attack_phase":     inv_def["attack_phase"],
            "mitre_tactic":     inv_def["mitre_tactic"],
            "mitre_technique":  inv_def["mitre_technique"],
            "weight":           inv_def["weight"],
            "detected_at":      timestamp,
            "invariant_source": inv_def["invariant_source"],
        })

    return violations


# ── PostgreSQL: 감사 로그 → 추가 위반 탐지 ─────────────────────────────────────

def fetch_db_violations(scan_time: datetime) -> list:
    """audit_logs 테이블에서 DENIED 이벤트를 읽어 위반을 추가 탐지한다."""
    if not HAS_PSYCOPG2:
        return []
    try:
        conn = psycopg2.connect(
            host=DB_HOST, database="argos_db",
            user="argos_app", password=DB_PASS,
            connect_timeout=5,
        )
        cur = conn.cursor()
        since = (scan_time - timedelta(hours=48)).isoformat()
        cur.execute("""
            SELECT action, resource_type, source_ip, created_at
            FROM audit_logs
            WHERE result = 'DENIED'
              AND created_at >= %s
            ORDER BY created_at DESC
            LIMIT 200
        """, (since,))
        rows = cur.fetchall()
        conn.close()

        extra: list = []
        # BOLA 탐지: GET_DEVICE / GET_VIDEO_URL DENIED 는 INV-STD-07 에 해당
        bola_actions = {"GET_DEVICE", "GET_VIDEO_URL", "GET_VIDEO"}
        seen_bola = False
        for action, resource_type, src_ip, created_at in rows:
            if action in bola_actions and not seen_bola:
                seen_bola = True
                inv_def = RULE_TO_INVARIANT[100007]
                zone = _ip_to_zone(src_ip or "") or inv_def["default_zone"]
                extra.append({
                    "id":               inv_def["id"],
                    "severity":         inv_def["severity"],
                    "description":      f"{inv_def['description']} — DB audit 탐지",
                    "server_zone":      zone,
                    "type":             inv_def["type"],
                    "attack_phase":     inv_def["attack_phase"],
                    "mitre_tactic":     inv_def["mitre_tactic"],
                    "mitre_technique":  inv_def["mitre_technique"],
                    "weight":           inv_def["weight"],
                    "detected_at":      created_at.isoformat() + "Z",
                    "invariant_source": inv_def["invariant_source"],
                })
        return extra
    except Exception as e:
        log.warning("DB audit fetch failed: %s", e)
        return []


def fetch_db_assets() -> list:
    """devices 테이블에서 자산 목록을 가져온다."""
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
            SELECT id::text, serial_number, model,
                   firmware_version, status, registered_at
            FROM devices
            ORDER BY registered_at DESC
            LIMIT 100
        """)
        rows = cur.fetchall()
        conn.close()

        assets = []
        for idx, (did, serial, model, fw_ver, status, reg_at) in enumerate(rows, 1):
            assets.append({
                "id":           f"ASSET-{serial}",
                "name":         serial,
                "type":         "IoT",
                "segment":      "내부망",
                "zone":         "운영",
                "ip":           f"10.20.{idx}.1",
                "os":           f"Argos FW {fw_ver or 'unknown'}",
                "os_age":       2,
                "online_status": "온라인" if status == "active" else "오프라인",
                "cvss_max":     None,
                "patch_status": "적용완료" if status == "active" else "미적용",
                "edr":          False,
                "av":           False,
                "managed":      True,
                "exposed":      False,
                "privilege":    "정상",
                "violation_ids": [],
                "last_seen":    reg_at.isoformat() + "Z" if reg_at else None,
            })
        return assets
    except Exception as e:
        log.warning("DB asset fetch failed: %s", e)
        return []


# ── 지표 계산 ─────────────────────────────────────────────────────────────────

_SEVERITY_COLORS = {
    "Critical": "#0C447C",
    "High":     "#185FA5",
    "Medium":   "#378ADD",
    "Low":      "#85B7EB",
}

_DEDUCTIONS = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}

_PHASE_WEIGHTS = {
    "초기침투": 29,
    "내부이동": 25,
    "권한상승": 22,
    "데이터탈취": 20,
}

_TYPE_COLORS = ["#0C447C", "#185FA5", "#378ADD", "#85B7EB", "#AECDE8"]


def calc_score(violations: list) -> int:
    total = sum(_DEDUCTIONS.get(v.get("severity", ""), 0) for v in violations)
    return max(0, 100 - total)


def calc_severity_distribution(violations: list) -> list:
    counts = {k: 0 for k in _SEVERITY_COLORS}
    for v in violations:
        if v["severity"] in counts:
            counts[v["severity"]] += 1
    return [{"name": k, "value": n, "color": _SEVERITY_COLORS[k]}
            for k, n in counts.items()]


def calc_zone_violations(violations: list) -> list:
    zone_counts: dict = {}
    for v in violations:
        z = v.get("server_zone", "기타")
        zone_counts[z] = zone_counts.get(z, 0) + 1
    return [{"zone": k, "count": n}
            for k, n in sorted(zone_counts.items(), key=lambda x: -x[1])]


def calc_type_violations(violations: list) -> list:
    type_counts: dict = {}
    for v in violations:
        t = v.get("type", "기타")
        type_counts[t] = type_counts.get(t, 0) + 1
    return [
        {"name": k, "value": n, "color": _TYPE_COLORS[i % len(_TYPE_COLORS)]}
        for i, (k, n) in enumerate(
            sorted(type_counts.items(), key=lambda x: -x[1])
        )
    ]


def calc_coverage(violations: list) -> dict:
    violated: dict = {p: 0 for p in _PHASE_WEIGHTS}
    for v in violations:
        phase = v.get("attack_phase")
        if phase in violated:
            violated[phase] += v.get("weight", 0)

    result = {}
    for phase, total in _PHASE_WEIGHTS.items():
        vw = min(violated[phase], total)
        result[phase] = {
            "total_weight":    total,
            "violated_weight": vw,
            "coverage_pct":    max(0, round((1 - vw / total) * 100)),
        }
    return result


# ── MITRE 매핑 생성 ────────────────────────────────────────────────────────────

def build_mitre_mapping(violations: list) -> list:
    tactic_tech: dict = {}
    for v in violations:
        tid = v.get("mitre_tactic", "")
        tech = v.get("mitre_technique", "")
        if not tid:
            continue
        tactic_tech.setdefault(tid, {})\
            .setdefault(tech, {"violation_ids": [], "severity": v["severity"]})\
            ["violation_ids"].append(v["id"])

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


# ── 공격 체인 생성 ─────────────────────────────────────────────────────────────

_PHASE_ORDER = ["초기침투", "내부이동", "권한상승", "데이터탈취"]


def build_attack_chains(violations: list) -> list:
    phase_map: dict = {}
    for v in violations:
        p = v.get("attack_phase", "")
        if p in _PHASE_ORDER:
            phase_map.setdefault(p, []).append(v)

    present = [p for p in _PHASE_ORDER if p in phase_map]
    if len(present) < 2:
        return []

    total_weight = sum(v.get("weight", 0) for v in violations)
    risk_score   = min(100, total_weight * 2)

    nodes, edges = [], []
    prev_id = None
    for i, phase in enumerate(present):
        nid = f"n{i + 1}"
        pv  = phase_map[phase][0]
        nodes.append({"id": nid, "label": phase, "violation_id": pv["id"], "phase": phase})
        if prev_id:
            edges.append({"from": prev_id, "to": nid})
        prev_id = nid

    kill_chain = [
        {
            "step":         i + 1,
            "phase":        phase,
            "violation_id": phase_map[phase][0]["id"],
            "mitre":        phase_map[phase][0].get("mitre_technique", ""),
            "description":  f"{phase_map[phase][0]['description']}",
        }
        for i, phase in enumerate(present)
    ]

    seen_tech: set = set()
    techniques = []
    for v in violations:
        tech = v.get("mitre_technique", "")
        if tech and tech not in seen_tech:
            seen_tech.add(tech)
            techniques.append({
                "id":          tech,
                "name":        TECHNIQUE_NAMES.get(tech, tech),
                "tactic":      v.get("mitre_tactic", ""),
                "violation_id": v["id"],
                "description": v["description"],
            })

    ids = {v["id"] for v in violations}
    if "INV-STD-01" in ids:
        title = "퇴직자 계정 활용 공격 체인"
    elif "INV-ARG-01" in ids or "INV-ARG-03" in ids:
        title = "테넌트 격리 위반 공격 체인"
    else:
        title = f"자동 탐지 공격 체인 — {present[0]} → {present[-1]}"

    return [{
        "chain_id":   "CHAIN-AUTO-001",
        "title":      title,
        "risk_score": risk_score,
        "nodes":      nodes,
        "edges":      edges,
        "kill_chain": kill_chain,
        "techniques": techniques,
        "procedures": [],
    }]


# ── 조치 방안 생성 ─────────────────────────────────────────────────────────────

_PRIORITY_ORDER = {"즉시": 0, "1주": 1, "1개월": 2}


def build_remediations(violations: list) -> list:
    seen: set = set()
    remediations = []

    inv_by_id = {d["id"]: d for d in RULE_TO_INVARIANT.values()}

    for v in violations:
        vid = v["id"]
        if vid in seen:
            continue
        seen.add(vid)
        inv_def = inv_by_id.get(vid, {})
        remediations.append({
            "violation_id": vid,
            "description":  inv_def.get("remediation", f"{v['description']} 조치 필요"),
            "attack_phase": v.get("attack_phase", ""),
            "priority":     inv_def.get("priority", "1개월"),
            "done":         False,
        })

    remediations.sort(key=lambda x: _PRIORITY_ORDER.get(x["priority"], 3))
    return remediations


# ── 메인 스캔 실행 ─────────────────────────────────────────────────────────────

def run_scan(scan_id: str) -> tuple:
    """
    스캔을 실행하고 (scan_item, scan_detail) 튜플을 반환한다.
    Wazuh/DB 연결 실패 시 빈 결과로 안전하게 계속 진행한다.
    """
    scan_time = datetime.utcnow()

    # 1. 데이터 수집
    alerts     = fetch_wazuh_alerts(hours=48)
    violations = alerts_to_violations(alerts, scan_time)

    db_violations = fetch_db_violations(scan_time)
    # DB 탐지 결과 중 Wazuh에서 이미 탐지하지 못한 항목만 추가
    existing_ids = {v["id"] for v in violations}
    for dv in db_violations:
        if dv["id"] not in existing_ids:
            violations.append(dv)
            existing_ids.add(dv["id"])

    assets = fetch_db_assets()

    # 2. 지표 계산
    score            = calc_score(violations)
    critical_high    = sum(1 for v in violations if v["severity"] in ("Critical", "High"))
    sev_dist         = calc_severity_distribution(violations)
    zone_viol        = calc_zone_violations(violations)
    type_viol        = calc_type_violations(violations)
    coverage         = calc_coverage(violations)
    mitre_mapping    = build_mitre_mapping(violations)
    attack_chains    = build_attack_chains(violations)
    remediations     = build_remediations(violations)

    # 3. 스캔 목록 항목
    scan_item = {
        "scan_id":    scan_id,
        "scanned_at": scan_time.isoformat() + "Z",
        "status":     "completed",
        "metrics": {
            "score":                   score,
            "total_violations":        len(violations),
            "critical_high":           critical_high,
            "attack_chains":           len(attack_chains),
            "vulnerable_asset_count":  len([a for a in assets if a.get("online_status") == "오프라인"]),
            "patch_rate":              round(
                len([a for a in assets if a.get("patch_status") == "적용완료"]) /
                max(len(assets), 1) * 100
            ),
        },
    }

    # 4. 스캔 세부 정보
    scan_detail = {
        "summary": {
            "total_violations": len(violations),
            "critical_high":    critical_high,
            "attack_chains":    len(attack_chains),
        },
        "violations":            violations,
        "severityDistribution":  sev_dist,
        "zoneViolations":        zone_viol,
        "typeViolations":        type_viol,
        "attackChains":          attack_chains,
        "mitreMapping":          mitre_mapping,
        "pentestResults":        [],   # 수동 입력용 (POST /scans/{id}/pentest 로 업데이트)
        "coverage":              coverage,
        "assets":                assets,
        "assetHistory":          [],
        "assetEvents":           [],
        "assetPolicies":         [],
        "remediations":          remediations,
        "softwareAssets":        [],
        "credentialAssets":      [],
        "apiAssets":             [],
    }

    return scan_item, scan_detail
