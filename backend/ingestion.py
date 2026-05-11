"""
AI Pack dashboard-db-ingestion-export.json ingestion.

The frontend never renders this export directly. This module is the backend
boundary that accepts AI Pack DB export rows and upserts them into PostgreSQL,
then the regular /api/scans and /api/scans/{scan_id}/details endpoints serve
UI-shaped responses from the database.
"""

import logging
from datetime import datetime

try:
    import psycopg2.extras
except ImportError:  # pragma: no cover - guarded by scanner.HAS_PSYCOPG2
    psycopg2 = None

from scanner import HAS_PSYCOPG2, _db_connect

log = logging.getLogger("ingestion")

TABLE_ORDER = [
    "scans",
    "assets",
    "services",
    "asset_services",
    "asset_related_invariants",
    "scan_asset_snapshot",
    "asset_events",
    "asset_history_monthly",
    "invariants",
    "violations",
    "violation_evidence",
    "violation_assets",
    "attack_chains",
    "attack_chain_steps",
    "attack_chain_invariants",
    "mitre_attack_flow",
    "mitre_flow_invariants",
    "scan_mitre_tactic_map",
    "invariant_impact",
    "invariant_impact_evidence",
    "invariant_impact_registry_assets",
    "invariant_impact_services",
    "evidence_events",
    "scan_severity_distribution",
    "scan_zone_violations",
    "scan_type_violations",
    "scan_coverage",
    "pentest_results",
    "pentest_related_invariants",
    "pentest_target_assets",
    "remediations",
]

BLOCKED_EVIDENCE_FIELDS = {
    "raw",
    "raw_event",
    "raw_payload",
    "raw_evidence",
    "token",
    "secret",
    "password",
    "private_key",
    "credential",
    "authorization",
    "cookie",
}


def _table_meta(cur, table_name: str) -> tuple[list[str], list[str]]:
    cur.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        ORDER BY ordinal_position
    """, (table_name,))
    columns = [row[0] for row in cur.fetchall()]
    cur.execute("""
        SELECT kcu.column_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
          ON tc.constraint_name = kcu.constraint_name
         AND tc.table_schema = kcu.table_schema
        WHERE tc.constraint_type = 'PRIMARY KEY'
          AND tc.table_schema = 'public'
          AND tc.table_name = %s
        ORDER BY kcu.ordinal_position
    """, (table_name,))
    pk_columns = [row[0] for row in cur.fetchall()]
    return columns, pk_columns


def _rows_for_table(export: dict, table_name: str) -> list[dict]:
    tables = export.get("tables", {})
    # AI Pack의 mitre_flow_invariants(스캔 단위)를 scan_mitre_tactic_map으로 매핑
    if table_name == "scan_mitre_tactic_map":
        source_rows = tables.get("mitre_flow_invariants", [])
        if not isinstance(source_rows, list):
            return []
        return [
            {
                "scan_id":      row.get("scan_id"),
                "tactic_id":    row.get("tactic_id"),
                "invariant_id": row.get("invariant_id"),
                "mapping_basis": row.get("mapping_basis"),
            }
            for row in source_rows
            if isinstance(row, dict) and row.get("scan_id") and row.get("tactic_id") and row.get("invariant_id")
        ]
    value = tables.get(table_name, [])
    if isinstance(value, dict):
        value = value.get("rows", value.get("items", []))
    if not isinstance(value, list):
        return []
    # export 필드명 → DB 컬럼명 매핑
    if table_name == "invariants":
        mapped = []
        for row in value:
            if not isinstance(row, dict):
                continue
            r = dict(row)
            if "title" in r and "description" not in r:
                r["description"] = r.pop("title") or r.get("invariant_id", "")
            if "catalog_status" in r and "approval_status" not in r:
                s = r.pop("catalog_status")
                r["approval_status"] = s if s in ("approved", "draft") else "approved"
            if "source" in r and "invariant_source" not in r:
                s = r.pop("source")
                r["invariant_source"] = s if s in ("fixed", "variable", "custom") else "fixed"
            # description이 invariant_id와 같으면 플레이스홀더이므로 제거 (기존 값 보존)
            if r.get("description") == r.get("invariant_id"):
                r.pop("description", None)
            mapped.append(r)
        return mapped
    if table_name == "services":
        mapped = []
        for row in value:
            if not isinstance(row, dict):
                continue
            r = dict(row)
            if "service_name" in r and "name" not in r:
                r["name"] = r.pop("service_name")
            if "owning_asset" in r and "owning_asset_id" not in r:
                r["owning_asset_id"] = r.pop("owning_asset")
            mapped.append(r)
        return mapped
    return value


def _sanitize_row(table_name: str, row: dict, allowed_columns: list[str]) -> dict:
    filtered = {key: value for key, value in row.items() if key in allowed_columns}
    if table_name == "evidence_events":
        filtered = {
            key: value
            for key, value in filtered.items()
            if key.lower() not in BLOCKED_EVIDENCE_FIELDS
        }
    return filtered


# ingest 시 ON CONFLICT UPDATE에서 덮어쓰지 않을 컬럼 (사용자가 직접 설정한 값 보호)
_PRESERVE_ON_CONFLICT: dict[str, set[str]] = {
    "invariants": {"invariant_source", "state", "approval_status"},
}


def _upsert_rows(cur, table_name: str, rows: list[dict]) -> int:
    if not rows:
        return 0

    columns, pk_columns = _table_meta(cur, table_name)
    if not columns:
        log.warning("Skipping unknown table in AI Pack export: %s", table_name)
        return 0
    if not pk_columns:
        log.warning("Skipping table without primary key for safe upsert: %s", table_name)
        return 0

    sanitized = [_sanitize_row(table_name, row, columns) for row in rows if isinstance(row, dict)]
    sanitized = [row for row in sanitized if all(row.get(pk) is not None for pk in pk_columns)]
    if not sanitized:
        return 0

    insert_columns = [column for column in columns if any(column in row for row in sanitized)]
    values = [tuple(row.get(column) for column in insert_columns) for row in sanitized]
    preserve = _PRESERVE_ON_CONFLICT.get(table_name, set())
    update_columns = [column for column in insert_columns if column not in pk_columns and column not in preserve]

    conflict = ", ".join(pk_columns)
    assignments = ", ".join(f"{column} = EXCLUDED.{column}" for column in update_columns)
    if assignments:
        query = f"""
            INSERT INTO {table_name} ({", ".join(insert_columns)})
            VALUES %s
            ON CONFLICT ({conflict}) DO UPDATE SET {assignments}
        """
    else:
        query = f"""
            INSERT INTO {table_name} ({", ".join(insert_columns)})
            VALUES %s
            ON CONFLICT ({conflict}) DO NOTHING
        """

    psycopg2.extras.execute_values(cur, query, values)
    return len(sanitized)


def ingest_dashboard_export(export: dict) -> dict:
    if not HAS_PSYCOPG2:
        return {
            "status": "db_unavailable",
            "ingested_at": datetime.utcnow().isoformat() + "Z",
            "tables": {},
            "error": "psycopg2 is not installed or PostgreSQL support is disabled.",
        }

    counts = {}
    try:
        conn = _db_connect()
        cur = conn.cursor()
        for table_name in TABLE_ORDER:
            rows = _rows_for_table(export, table_name)
            counts[table_name] = _upsert_rows(cur, table_name, rows)
        conn.commit()
        conn.close()
        return {
            "status": "ok",
            "ingested_at": datetime.utcnow().isoformat() + "Z",
            "source": export.get("source", "ai_pack_db_ingestion_export"),
            "scan_id": export.get("scan_id") or export.get("run_id"),
            "tables": counts,
        }
    except Exception as exc:
        log.exception("AI Pack DB ingestion export upsert failed")
        try:
            conn.rollback()
            conn.close()
        except Exception:
            pass
        return {
            "status": "failed",
            "ingested_at": datetime.utcnow().isoformat() + "Z",
            "tables": counts,
            "error": str(exc),
        }
