-- =============================================================================
-- ARGOS Security Dashboard DB Schema v2
-- 기준: 시나리오1_인프라_SIEM_Evidence_수집_최종본_ver3.md
-- DB:   PostgreSQL (localhost on argos-security)
--
-- 설계 원칙
--   1. 정규화: M:N 관계는 junction table, 파생값은 저장 안 함
--   2. JSONB: event_type별로 구조가 다른 observed 필드에 사용 (GIN 인덱스)
--   3. TEXT[]: 단순 표시용 목록 (join 불필요한 경우)
--   4. UI 전용: color, 한국어 type label 등은 API 레이어에서 처리
--   5. 민감 원문 비저장: IP 원문 대신 source_ip_class, JWT 원문 없음
-- =============================================================================


-- =============================================================================
-- GROUP 1. 불변식 (Invariants)
-- 근거: ver3 섹션 9.1, 11
-- =============================================================================

CREATE TABLE invariants (
    invariant_id        VARCHAR     PRIMARY KEY,   -- INV-STD-01~14, INV-ARG-01~08
    description         TEXT        NOT NULL,
    invariant_source    VARCHAR     NOT NULL       CHECK (invariant_source IN ('fixed', 'variable')),
    severity            VARCHAR                    CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
    default_zone        VARCHAR,                   -- ops | dmz | db | deploy | security
    category            VARCHAR,                   -- 접근제어 | 권한 | 보안정책 | 네트워크
    weight              INTEGER     CHECK (weight BETWEEN 1 AND 10),
    attack_phase        VARCHAR                    CHECK (attack_phase IN (
                            '초기침투',            -- Initial Access: JWT 위조 토큰, 내부 API 직접 접근
                            '자격증명',            -- Credential Access: 퇴직자 키 접근, 키 미회전
                            '권한상승',            -- Privilege Escalation: 과도한 권한, owner/tenant 검증 누락
                            '방어우회',            -- Defense Evasion: 로그 단절, 탐지 실패
                            '데이터탈취'           -- Exfiltration: IDOR, 테넌트 격리 위반, 민감정보 노출
                        )),
    remediation_default TEXT
);


-- =============================================================================
-- GROUP 2. 자산 & 서비스
-- 근거: ver3 섹션 10 producer.vm 구조, migration guide 4.3/4.4
-- =============================================================================

CREATE TABLE assets (
    asset_id            VARCHAR     PRIMARY KEY,
    asset_name          VARCHAR     NOT NULL,
    asset_type          VARCHAR     NOT NULL,      -- application_audit_log | auth_service | signing_service | iot_device | network_device 등
    asset_category      VARCHAR                    CHECK (asset_category IN ('server', 'endpoint', 'iot', 'network')),
    observation_status  VARCHAR                    CHECK (observation_status IN ('registered', 'unregistered_asset_candidate')),
    zone                VARCHAR,                   -- ops | dmz | db | deploy | security | management 등
    vm                  VARCHAR,                   -- argos-ops | argos-dmz 등 (실제 VM과 1:1)
    ip_hint             VARCHAR,
    criticality         VARCHAR                    CHECK (criticality IN ('high', 'medium', 'low', 'unknown')),
    exposure            VARCHAR                    CHECK (exposure IN ('internet', 'internal', 'isolated', 'unknown')),
    -- 식별 및 소유권
    company_id          VARCHAR,                   -- 테넌트/기업 ID (multi-tenant 환경)
    snapshot_id         VARCHAR,                   -- 자산이 등록된 스냅샷 ID
    -- Evidence 참조 (wazuh 등에서 관측된 evidence_id 목록)
    evidence_refs       TEXT[],
    -- 표시용 배열 (join 불필요)
    data_classes        TEXT[],                    -- customer_pii | video 등
    observed_sources    TEXT[],                    -- wazuh 등
    kisa_sheets         TEXT[],
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    record_hash         VARCHAR
);

-- 자산 ↔ 불변식 (M:N)
CREATE TABLE asset_related_invariants (
    asset_id        VARCHAR NOT NULL REFERENCES assets(asset_id),
    invariant_id    VARCHAR NOT NULL REFERENCES invariants(invariant_id),
    PRIMARY KEY (asset_id, invariant_id)
);

CREATE TABLE services (
    service_id          VARCHAR     PRIMARY KEY,
    name                VARCHAR     NOT NULL,
    owning_asset_id     VARCHAR     REFERENCES assets(asset_id),
    vm                  VARCHAR,
    zone                VARCHAR,
    component_type      VARCHAR,                   -- application_api | database | siem | state_collector | gateway | signing_service 등
    deployment_ref      VARCHAR,
    log_source_refs     TEXT[],
    collected_by_wazuh  BOOLEAN,
    observation_status  VARCHAR                    CHECK (observation_status IN ('registered', 'unregistered_service_candidate'))
);

-- 자산 ↔ 서비스 관계 (all = linked ∪ observed, 파생값이므로 저장 안 함)
CREATE TABLE asset_services (
    asset_id            VARCHAR NOT NULL REFERENCES assets(asset_id),
    service_id          VARCHAR NOT NULL REFERENCES services(service_id),
    relationship_type   VARCHAR NOT NULL           CHECK (relationship_type IN ('linked', 'observed')),
    PRIMARY KEY (asset_id, service_id, relationship_type)
);


-- =============================================================================
-- GROUP 3. 스캔
-- =============================================================================

CREATE TABLE scans (
    scan_id                 VARCHAR     PRIMARY KEY,
    snapshot_id             VARCHAR,
    scanned_at              TIMESTAMPTZ NOT NULL,
    status                  VARCHAR     NOT NULL   CHECK (status IN ('completed', 'running', 'failed')),
    score                   INTEGER,
    total_violations        INTEGER     DEFAULT 0,
    critical_high           INTEGER     DEFAULT 0,
    attack_chains_count     INTEGER     DEFAULT 0,
    asset_count             INTEGER     DEFAULT 0,
    service_count           INTEGER     DEFAULT 0
);

-- 스캔별 자산 현황 스냅샷 (날짜별 자산 추이 그래프용)
-- patch 관련 컬럼 제외: 현재 파이프라인에 패치 상태 수집 구조 없음
CREATE TABLE scan_asset_snapshot (
    scan_id          VARCHAR  PRIMARY KEY REFERENCES scans(scan_id),
    total            INTEGER  DEFAULT 0,  -- 전체 자산 수
    registered       INTEGER  DEFAULT 0,  -- observation_status = 'registered'
    unregistered     INTEGER  DEFAULT 0,  -- observation_status = 'unregistered_asset_candidate'
    with_violation   INTEGER  DEFAULT 0,  -- violation 영향 자산 수 (violation_assets 집계)
    online           INTEGER  DEFAULT 0,  -- online_status = '온라인'
    offline          INTEGER  DEFAULT 0,  -- online_status = '오프라인'
    server_count     INTEGER  DEFAULT 0,  -- asset_category = 'server'
    endpoint_count   INTEGER  DEFAULT 0,  -- asset_category = 'endpoint'
    iot_count        INTEGER  DEFAULT 0,  -- asset_category = 'iot'
    network_count    INTEGER  DEFAULT 0   -- asset_category = 'network'
);

-- event_type별 Evidence 수집 상태
CREATE TABLE evidence_type_coverage (
    scan_id             VARCHAR NOT NULL REFERENCES scans(scan_id),
    evidence_type       VARCHAR NOT NULL,
    expected_in_final   BOOLEAN,
    collected_count     INTEGER DEFAULT 0,
    collection_status   VARCHAR                    CHECK (collection_status IN ('collected', 'not_collected_yet')),
    PRIMARY KEY (scan_id, evidence_type)
);


-- =============================================================================
-- GROUP 4. Evidence
-- 근거: ver3 섹션 8 공통 포맷, 섹션 10 event_type별 필드
--
-- 설계:
--   공통 필드 → 개별 컬럼 (인덱스, 빈번 필터링)
--   observed  → JSONB (event_type별 구조 상이, 13개 타입 테이블 대신)
--   timestamp 기준 월별 파티셔닝 (SIEM 누적 데이터 대비)
--   민감 원문 비저장: actor_source_ip → ip_class만, JWT 원문 없음
-- =============================================================================

CREATE TABLE evidence_events (
    evidence_id             VARCHAR     NOT NULL,
    timestamp               TIMESTAMPTZ NOT NULL,
    schema_version          VARCHAR,               -- argos-siem-event-v1
    trace_id                VARCHAR,
    request_id              VARCHAR,
    event_category          VARCHAR     NOT NULL   CHECK (event_category IN ('attack_execution', 'environment_state')),
    evidence_type           VARCHAR     NOT NULL,  -- account_state_event | token_policy_state | api_authorization_event | gateway_access_event | data_access_event | aggregation_state | log_trace_state | log_retention_state | key_management_state 등
    -- producer (ver3 섹션 8)
    producer_vm             VARCHAR,               -- argos-ops | argos-dmz 등
    producer_component_id   VARCHAR,
    producer_component_type VARCHAR,               -- api | gateway | database | state_collector | detector | normalizer 등
    producer_zone           VARCHAR,
    producer_asset_id       VARCHAR,               -- Evidence Normalizer 추가
    producer_service_id     VARCHAR,               -- Evidence Normalizer 추가
    -- actor (Evidence Normalizer, 원문 IP 비저장)
    actor_id                VARCHAR,
    actor_role              VARCHAR,
    actor_source_ip_class   VARCHAR                CHECK (actor_source_ip_class IN ('external', 'internal', 'vpn', NULL)),
    -- token (Evidence Normalizer, 원문 비저장)
    token_present           BOOLEAN,
    token_sub               VARCHAR,
    token_tenant            VARCHAR,
    token_kid               VARCHAR,               -- JWT header kid 참조값 (원문 아님)
    token_jti               VARCHAR,               -- JWT ID 참조값 (원문 아님)
    token_signature_valid   BOOLEAN,
    token_issued_by_auth_server BOOLEAN,
    token_revoked           BOOLEAN,
    -- access (Evidence Normalizer)
    access_action           VARCHAR,
    access_endpoint         VARCHAR,
    access_method           VARCHAR,               -- GET | POST | PUT | DELETE
    access_decision         VARCHAR                CHECK (access_decision IN ('allow', 'block', 'detect', NULL)),
    access_status_code      INTEGER,
    -- target asset (Evidence Normalizer)
    target_asset_id         VARCHAR,
    target_asset_type       VARCHAR,
    target_asset_owner_id   VARCHAR,
    target_asset_tenant_id  VARCHAR,
    -- control (Evidence Normalizer)
    control_owner_check_performed   BOOLEAN,
    control_tenant_check_performed  BOOLEAN,
    control_authz_service_used      BOOLEAN,
    -- raw_ref (민감 원문 없음, 위치 참조만)
    raw_ref_source          VARCHAR,               -- wazuh | opensearch 등
    raw_ref_agent           VARCHAR,
    raw_ref_location        VARCHAR,               -- /var/log/argos/*.jsonl
    raw_ref_log_id          VARCHAR,
    -- event_type별 observed 전체 (JSONB, ver3 섹션 10 모든 타입 수용)
    observed                JSONB,
    PRIMARY KEY (evidence_id, timestamp)
) PARTITION BY RANGE (timestamp);

-- 월별 파티션 (운영 시 자동화 필요)
CREATE TABLE evidence_events_2026_05
    PARTITION OF evidence_events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE TABLE evidence_events_2026_06
    PARTITION OF evidence_events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE INDEX idx_evidence_type        ON evidence_events (evidence_type);
CREATE INDEX idx_evidence_trace       ON evidence_events (trace_id);
CREATE INDEX idx_evidence_actor       ON evidence_events (actor_id);
CREATE INDEX idx_evidence_category    ON evidence_events (event_category);
CREATE INDEX idx_evidence_producer    ON evidence_events (producer_asset_id);
CREATE INDEX idx_evidence_observed    ON evidence_events USING GIN (observed);


-- =============================================================================
-- GROUP 5. AI1 결과
-- 근거: ver3 섹션 11, migration guide 4.2
-- =============================================================================

CREATE TABLE violations (
    result_id                       VARCHAR     PRIMARY KEY,
    scan_id                         VARCHAR     NOT NULL REFERENCES scans(scan_id),
    invariant_id                    VARCHAR     NOT NULL REFERENCES invariants(invariant_id),
    status                          VARCHAR     NOT NULL   CHECK (status IN ('applied', 'violated')),
    violation_reason                VARCHAR                CHECK (violation_reason IN (
                                        'clear_violation', 'partial_satisfaction', 'not_determined',
                                        'evidence_missing', 'log_trace_gap',
                                        'control_not_observed', 'environment_not_ready', NULL
                                    )),
    summary                         TEXT,
    reason                          TEXT,
    confidence                      NUMERIC                CHECK (confidence BETWEEN 0 AND 1),
    current_environment_testable    BOOLEAN,
    testability_reason              TEXT,
    created_at                      TIMESTAMPTZ
);

CREATE INDEX idx_violations_scan        ON violations (scan_id);
CREATE INDEX idx_violations_invariant   ON violations (invariant_id);
CREATE INDEX idx_violations_status      ON violations (status);

-- violations ↔ evidence_events (M:N)
CREATE TABLE violation_evidence (
    violation_id    VARCHAR NOT NULL REFERENCES violations(result_id),
    evidence_id     VARCHAR NOT NULL,
    PRIMARY KEY (violation_id, evidence_id)
);

-- violations ↔ assets (M:N)
CREATE TABLE violation_assets (
    violation_id    VARCHAR NOT NULL REFERENCES violations(result_id),
    asset_id        VARCHAR NOT NULL REFERENCES assets(asset_id),
    PRIMARY KEY (violation_id, asset_id)
);


-- =============================================================================
-- GROUP 6. AI2 결과 (attack_chains)
-- 근거: migration guide 4.7 AI2 chain item
-- =============================================================================

CREATE TABLE attack_chains (
    chain_scenario_id               VARCHAR     PRIMARY KEY,
    scan_id                         VARCHAR     NOT NULL REFERENCES scans(scan_id),
    created_at                      TIMESTAMPTZ,
    title                           VARCHAR,
    source_bundle_id                VARCHAR,
    risk_level                      VARCHAR                CHECK (risk_level IN ('critical', 'high', 'medium', 'low')),
    scenario_basis_status           VARCHAR,
    scenario_basis_violation_reason VARCHAR,
    scenario_basis_summary          TEXT,
    current_environment_testable    BOOLEAN,
    testability_reason              TEXT
);

-- 공격 체인 단계 (순서 보존 필요)
CREATE TABLE attack_chain_steps (
    id          SERIAL  PRIMARY KEY,
    chain_id    VARCHAR NOT NULL REFERENCES attack_chains(chain_scenario_id),
    step_order  INTEGER NOT NULL,
    step_text   TEXT    NOT NULL,
    UNIQUE (chain_id, step_order)
);

-- attack_chains ↔ invariants (M:N)
CREATE TABLE attack_chain_invariants (
    chain_id        VARCHAR NOT NULL REFERENCES attack_chains(chain_scenario_id),
    invariant_id    VARCHAR NOT NULL REFERENCES invariants(invariant_id),
    PRIMARY KEY (chain_id, invariant_id)
);

-- MITRE ATT&CK 흐름
-- MITRE 매핑은 AI2 chain 생성 시 이 테이블에 저장
CREATE TABLE mitre_attack_flow (
    id          SERIAL  PRIMARY KEY,
    chain_id    VARCHAR NOT NULL REFERENCES attack_chains(chain_scenario_id),
    flow_order  INTEGER NOT NULL,
    tactic      VARCHAR,            -- TA0001 등 전술
    technique   VARCHAR,            -- T1078 등 기법
    step        TEXT,
    reason      TEXT,
    UNIQUE (chain_id, flow_order)
);

-- mitre_attack_flow ↔ invariants (M:N)
CREATE TABLE mitre_flow_invariants (
    flow_id         INTEGER NOT NULL REFERENCES mitre_attack_flow(id),
    invariant_id    VARCHAR NOT NULL REFERENCES invariants(invariant_id),
    PRIMARY KEY (flow_id, invariant_id)
);

-- 수동 검증 가이드 (단순 목록이므로 JSONB 배열로 저장, child 4개 테이블 불필요)
CREATE TABLE validation_guide (
    chain_id            VARCHAR     PRIMARY KEY REFERENCES attack_chains(chain_scenario_id),
    goal                TEXT,
    steps               JSONB,      -- [{"order": 1, "text": "..."}, ...]
    success_criteria    JSONB,      -- ["...", "..."]
    evidence_to_collect JSONB,      -- ["...", "..."]
    safety_boundary     JSONB       -- ["...", "..."]
);


-- =============================================================================
-- GROUP 7. Red Team 결과
-- 근거: migration guide 8.7 Red Team validation result
-- =============================================================================

CREATE TABLE pentest_results (
    test_id                     VARCHAR     PRIMARY KEY,
    schema_version              VARCHAR,               -- argos-redteam-result-v3
    scan_id                     VARCHAR     NOT NULL REFERENCES scans(scan_id),
    scenario_id                 VARCHAR     REFERENCES attack_chains(chain_scenario_id),
    tester                      VARCHAR,
    tested_at                   TIMESTAMPTZ,
    overall_verdict             VARCHAR                CHECK (overall_verdict IN ('reproduced', 'partially_reproduced', 'not_reproduced', 'in_progress')),
    attack_input_and_process    TEXT,
    observed_result             TEXT,
    impact_assessment           TEXT,
    evidence_description        TEXT,
    additional_notes            TEXT
);

-- pentest_results ↔ invariants (M:N)
CREATE TABLE pentest_related_invariants (
    test_id         VARCHAR NOT NULL REFERENCES pentest_results(test_id),
    invariant_id    VARCHAR NOT NULL REFERENCES invariants(invariant_id),
    PRIMARY KEY (test_id, invariant_id)
);

-- pentest_results ↔ assets (M:N)
CREATE TABLE pentest_target_assets (
    test_id         VARCHAR NOT NULL REFERENCES pentest_results(test_id),
    asset_id        VARCHAR NOT NULL REFERENCES assets(asset_id),
    asset_type      VARCHAR,
    PRIMARY KEY (test_id, asset_id)
);


-- =============================================================================
-- GROUP 8. 조치 항목 (Remediations)
-- 방어 방안 및 보안 수준 페이지의 개선 권고 목록 관리
-- =============================================================================

CREATE TABLE remediations (
    id              SERIAL      PRIMARY KEY,
    invariant_id    VARCHAR     NOT NULL REFERENCES invariants(invariant_id),
    scan_id         VARCHAR     REFERENCES scans(scan_id),
    description     TEXT        NOT NULL,
    attack_phase    VARCHAR,
    priority        VARCHAR                        CHECK (priority IN ('즉시', '1주', '1개월')),
    done            BOOLEAN     DEFAULT FALSE,
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_remediations_scan ON remediations (scan_id);


-- =============================================================================
-- 비활성화 테이블 (필요 시 활성화)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- [비활성] 집계 스냅샷 4개
-- 이유: violations JOIN invariants에서 GROUP BY로 실시간 집계 가능.
--       스캔 수가 적은 현 단계에서는 쿼리 비용이 낮아 별도 저장 불필요.
--       스캔이 수백 건 이상 쌓이거나 대시보드 응답 지연이 발생하면 그때 활성화.
-- -----------------------------------------------------------------------------
/*
CREATE TABLE scan_severity_distribution (
    scan_id     VARCHAR NOT NULL REFERENCES scans(scan_id),
    severity    VARCHAR NOT NULL                   CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
    count       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scan_id, severity)
);

CREATE TABLE scan_zone_violations (
    scan_id VARCHAR NOT NULL REFERENCES scans(scan_id),
    zone    VARCHAR NOT NULL,
    count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scan_id, zone)
);

CREATE TABLE scan_type_violations (
    scan_id     VARCHAR NOT NULL REFERENCES scans(scan_id),
    type_name   VARCHAR NOT NULL,
    count       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scan_id, type_name)
);

CREATE TABLE scan_coverage (
    scan_id         VARCHAR NOT NULL REFERENCES scans(scan_id),
    attack_phase    VARCHAR NOT NULL,
    total_weight    INTEGER,
    violated_weight INTEGER,
    coverage_pct    INTEGER,
    PRIMARY KEY (scan_id, attack_phase)
);
*/

-- =============================================================================
-- GROUP 9. 자산 영향 요약 (Invariant Impact)
-- 근거: migration guide 4.5 — 반드시 추가해야 할 필드
-- violations + violation_assets JOIN으로 파생 가능하지만,
-- affected_resource_ids(업무 자원), affected_services, affected_zones를
-- 명시적으로 저장해 보안 관리자가 자산 중심으로 직접 탐색할 수 있도록 한다.
-- =============================================================================

CREATE TABLE invariant_impact (
    id                      SERIAL      PRIMARY KEY,
    invariant_id            VARCHAR     NOT NULL REFERENCES invariants(invariant_id),
    result_id               VARCHAR     NOT NULL REFERENCES violations(result_id),
    scan_id                 VARCHAR     NOT NULL REFERENCES scans(scan_id),
    status                  VARCHAR,
    violation_reason        VARCHAR,
    severity                VARCHAR,
    summary                 TEXT,
    affected_resource_ids   TEXT[],    -- 고객 ID, 기기 ID 등 업무 자원
    affected_zones          TEXT[]     -- 영향받은 zone 목록
);

CREATE INDEX idx_invariant_impact_scan     ON invariant_impact (scan_id);
CREATE INDEX idx_invariant_impact_inv      ON invariant_impact (invariant_id);

-- invariant_impact ↔ evidence_events (M:N)
CREATE TABLE invariant_impact_evidence (
    impact_id   INTEGER NOT NULL REFERENCES invariant_impact(id),
    evidence_id VARCHAR NOT NULL,
    PRIMARY KEY (impact_id, evidence_id)
);

-- invariant_impact ↔ assets (영향받는 registry 자산)
CREATE TABLE invariant_impact_registry_assets (
    impact_id   INTEGER NOT NULL REFERENCES invariant_impact(id),
    asset_id    VARCHAR NOT NULL REFERENCES assets(asset_id),
    PRIMARY KEY (impact_id, asset_id)
);

-- invariant_impact ↔ services (영향받는 서비스)
CREATE TABLE invariant_impact_services (
    impact_id   INTEGER NOT NULL REFERENCES invariant_impact(id),
    service_id  VARCHAR NOT NULL REFERENCES services(service_id),
    PRIMARY KEY (impact_id, service_id)
);

-- -----------------------------------------------------------------------------
-- [비활성] 자산 부속 인벤토리 (소프트웨어 / 자격증명 / API)
-- 이유: key/credential 상태는 key_management_state, account_state_event 등
--       evidence_events로 수집됨. 별도 인벤토리 테이블 불필요.
-- -----------------------------------------------------------------------------
/*
CREATE TABLE software_assets (
    sw_id           VARCHAR     PRIMARY KEY,
    name            VARCHAR     NOT NULL,
    sw_type         VARCHAR,
    version         VARCHAR,
    linked_asset_id VARCHAR     REFERENCES assets(asset_id),
    cve_count       INTEGER     DEFAULT 0,
    patch_status    VARCHAR                        CHECK (patch_status IN ('적용완료', '미적용', '지연')),
    eol             BOOLEAN     DEFAULT FALSE,
    severity        VARCHAR                        CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
    last_updated    DATE
);

CREATE TABLE software_asset_invariants (
    sw_id           VARCHAR NOT NULL REFERENCES software_assets(sw_id),
    invariant_id    VARCHAR NOT NULL REFERENCES invariants(invariant_id),
    PRIMARY KEY (sw_id, invariant_id)
);

CREATE TABLE credential_assets (
    cred_id         VARCHAR     PRIMARY KEY,
    name            VARCHAR     NOT NULL,
    cred_type       VARCHAR,
    owner           VARCHAR,
    storage         VARCHAR,
    mfa             BOOLEAN,
    last_rotated    DATE,
    expires_at      DATE,
    exposed         BOOLEAN     DEFAULT FALSE,
    privilege       VARCHAR                        CHECK (privilege IN ('정상', '과다', '최고')),
    severity        VARCHAR                        CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
    status          VARCHAR                        CHECK (status IN ('위험', '취약', '만료임박', '정상'))
);

CREATE TABLE credential_asset_invariants (
    cred_id         VARCHAR NOT NULL REFERENCES credential_assets(cred_id),
    invariant_id    VARCHAR NOT NULL REFERENCES invariants(invariant_id),
    PRIMARY KEY (cred_id, invariant_id)
);

CREATE TABLE api_assets (
    api_id          VARCHAR     PRIMARY KEY,
    name            VARCHAR     NOT NULL,
    api_type        VARCHAR,
    endpoint        VARCHAR,
    auth            VARCHAR,
    scope           VARCHAR,
    exposed         BOOLEAN     DEFAULT FALSE,
    rate_limit      BOOLEAN     DEFAULT FALSE,
    version         VARCHAR,
    linked_asset_id VARCHAR     REFERENCES assets(asset_id),
    status          VARCHAR                        CHECK (status IN ('정상', '취약', '위험')),
    last_audited    DATE
);

CREATE TABLE api_asset_invariants (
    api_id          VARCHAR NOT NULL REFERENCES api_assets(api_id),
    invariant_id    VARCHAR NOT NULL REFERENCES invariants(invariant_id),
    PRIMARY KEY (api_id, invariant_id)
);
*/

-- -----------------------------------------------------------------------------
-- [비활성] 자산 이벤트
-- 이유: Wazuh alert는 evidence_events의 wazuh_alert_event로 이미 수집됨. 중복 저장.
-- -----------------------------------------------------------------------------
/*
CREATE TABLE asset_events (
    event_id    VARCHAR     PRIMARY KEY,
    event_type  VARCHAR,
    asset_id    VARCHAR     REFERENCES assets(asset_id),
    asset_name  VARCHAR     NOT NULL,
    description TEXT,
    zone        VARCHAR,
    occurred_at TIMESTAMPTZ,
    severity    VARCHAR                            CHECK (severity IN ('Critical', 'High', 'Medium', 'Low'))
);

CREATE INDEX idx_asset_events_asset ON asset_events (asset_id);
CREATE INDEX idx_asset_events_time  ON asset_events (occurred_at DESC);
*/

-- -----------------------------------------------------------------------------
-- [비활성] 자산 현황 월별 이력
-- 이유: 월별 배치 집계를 자동으로 실행할 구조(스케줄러 등)가 현재 없음.
--       채울 데이터 수집 파이프라인이 구현되기 전까지 테이블만 있어도 의미 없음.
-- -----------------------------------------------------------------------------
/*
CREATE TABLE asset_history_monthly (
    id                  SERIAL      PRIMARY KEY,
    date_label          VARCHAR     NOT NULL,
    period_start        DATE        NOT NULL UNIQUE,
    total               INTEGER,
    vulnerable          INTEGER,
    vulnerable_hw       INTEGER,
    vulnerable_sw       INTEGER,
    vulnerable_cred     INTEGER,
    vulnerable_api      INTEGER,
    offline             INTEGER,
    patch_pct           INTEGER,
    patch_pct_hw        INTEGER,
    patch_pct_sw        INTEGER,
    unregistered        INTEGER,
    new_assets          INTEGER,
    policy_violations   INTEGER
);
*/
