-- =============================================================================
-- Migration: AI1 Traces + Violation/Invariant 컬럼 확장
-- 적용 대상: 기존 argos_security DB (schema.sql 이미 적용된 환경)
-- 실행: psql -U argos_app -d argos_security -f schema_migration_ai1_traces.sql
-- =============================================================================

-- violations: AI Pack 확장 필드 추가
ALTER TABLE violations ADD COLUMN IF NOT EXISTS judgment_summary TEXT;
ALTER TABLE violations ADD COLUMN IF NOT EXISTS missing_evidence_fields TEXT[] DEFAULT '{}';
ALTER TABLE violations ADD COLUMN IF NOT EXISTS affected_assets         TEXT[] DEFAULT '{}';
ALTER TABLE violations ADD COLUMN IF NOT EXISTS affected_resources      TEXT[] DEFAULT '{}';

-- AI1 트레이스 테이블 신규 생성
CREATE TABLE IF NOT EXISTS ai1_traces (
    scan_id                  VARCHAR     NOT NULL REFERENCES scans(scan_id),
    invariant_id             VARCHAR     NOT NULL REFERENCES invariants(invariant_id),
    result_id                VARCHAR     REFERENCES violations(result_id),
    context_pack_id          VARCHAR,
    evidence_refs            TEXT[]      DEFAULT '{}',
    required_evidence_types  TEXT[]      DEFAULT '{}',
    decision_basis           TEXT,
    verification_logic       TEXT,
    missing_fields           TEXT[]      DEFAULT '{}',
    evidence_summaries       JSONB       DEFAULT '[]'::jsonb,
    PRIMARY KEY (scan_id, invariant_id)
);

CREATE INDEX IF NOT EXISTS idx_ai1_traces_scan   ON ai1_traces (scan_id);
CREATE INDEX IF NOT EXISTS idx_ai1_traces_result ON ai1_traces (result_id);

-- 권한 부여 (기존 role과 동일)
GRANT SELECT, INSERT, UPDATE, DELETE ON ai1_traces TO argos_app;
