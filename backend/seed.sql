-- =============================================================================
-- ARGOS Security Dashboard — 테스트 시드 데이터
-- 스키마: schema.sql (v2) 기준
-- 시나리오: JWT 서명키 유출 기반 개인정보 탈취 (시나리오1 ver3)
--
-- SCAN-20260506-001 (2026-05-06): 공격 실행 단계 포착
--   INV-STD-01 — 퇴직자 계정 활성 상태
--   INV-STD-05 — 외부 발급 위조 토큰 접근
--   INV-ARG-01 — 테넌트 격리 위반
--
-- SCAN-20260507-001 (2026-05-07): 근본 원인 환경 상태 포착
--   INV-STD-04 — 퇴직자 접근 후 키 미회전
--   INV-STD-06 — JWT 토큰 검증 정책 미흡
--   INV-STD-08 — DMZ 내부 API 외부 노출
--
-- 공격 흐름:
--   exuser1(퇴직자) → jwt-key-2025-old(미회전 키)로 위조 토큰 생성
--   → argos-dmz 게이트웨이 통과 (내부 API 외부 노출)
--   → argos-ops /internal/api 접근 (tenant_a → tenant_b 데이터 탈취)
-- =============================================================================


-- =============================================================================
-- GROUP 1. 불변식
-- =============================================================================

INSERT INTO invariants
    (invariant_id, description, invariant_source, severity, default_zone, category, weight, attack_phase, remediation_default)
VALUES
    ('INV-STD-01', '퇴직자 계정 활성 상태 — 로그인 시도 탐지',
     'fixed', 'High', 'ops', '접근제어', 7, '자격증명',
     '퇴직자 계정 즉시 비활성화, IAM 연동 자동화, 세션·API Key 전수 회수'),

    ('INV-STD-04', '퇴직자 접근 이후 JWT 서명키 미회전',
     'fixed', 'Critical', 'ops', '접근제어', 10, '자격증명',
     '퇴직자 키 접근 이력 확인 즉시 서명키 교체, 키 회전 자동화 구축'),

    ('INV-STD-05', '인증 서버 외부 발급 토큰으로 내부 API 접근 성공',
     'fixed', 'Critical', 'ops', '접근제어', 10, '초기침투',
     '토큰 발급처(issuer) 검증 강화, kid 활성 여부 검증, JTI registry 도입'),

    ('INV-STD-06', 'JWT 토큰 검증 정책 미흡 — issuer/kid/revocation 미검증',
     'fixed', 'High', 'ops', '보안정책', 8, '방어우회',
     'validate_issuer·validate_kid_active·validate_jti_registry 정책 활성화'),

    ('INV-STD-08', 'DMZ에서 내부 API 경로 외부 노출 — /internal/* 차단 미적용',
     'fixed', 'Critical', 'dmz', '네트워크', 9, '초기침투',
     'DMZ 게이트웨이에서 /internal/* 경로 외부 접근 차단, WAF 규칙 추가'),

    ('INV-ARG-01', '테넌트(기업) 간 데이터 처리 위반 — tenant 격리 검증 미적용',
     'variable', 'Critical', 'ops', '접근제어', 10, '데이터탈취',
     '모든 API에 tenant_check 미들웨어 적용, Authz Service 통한 테넌트 격리 의무화')

ON CONFLICT (invariant_id) DO NOTHING;


-- =============================================================================
-- GROUP 2. 자산
-- =============================================================================

INSERT INTO assets
    (asset_id, asset_name, asset_type, asset_category, observation_status, zone, vm, ip_hint,
     criticality, exposure,
     company_id, snapshot_id, evidence_refs,
     data_classes, observed_sources, kisa_sheets,
     first_seen, last_seen, record_hash)
VALUES
    ('APP-OPS-001', 'argos-ops API 서버', 'application_audit_log', 'server', 'registered',
     'ops', 'argos-ops', '10.10.3.x', 'high', 'internal',
     'tenant-internal', 'asset-snapshot-20260506090000',
     ARRAY['evd-s1-account-state-001', 'evd-s1-api-authz-001', 'evd-s1-token-policy-001', 'evd-s1-key-state-001'],
     ARRAY['customer_pii'], ARRAY['wazuh'], ARRAY['KISA-IAM-01'],
     '2026-04-01 00:00:00+09', '2026-05-07 09:00:00+09', 'hash-ops-001'),

    ('APP-DMZ-001', 'argos-dmz 게이트웨이', 'network_device', 'network', 'registered',
     'dmz', 'argos-dmz', '10.10.1.x', 'high', 'internet',
     'tenant-internal', 'asset-snapshot-20260506090000',
     ARRAY['evd-s1-gateway-access-001'],
     ARRAY[]::TEXT[], ARRAY['wazuh'], ARRAY['KISA-NET-01'],
     '2026-04-01 00:00:00+09', '2026-05-07 09:00:00+09', 'hash-dmz-001'),

    ('APP-DATA-001', 'argos-data DB 서버', 'auth_service', 'server', 'registered',
     'db', 'argos-data', '10.10.4.x', 'high', 'isolated',
     'tenant-internal', 'asset-snapshot-20260506090000',
     ARRAY['evd-s1-data-access-001'],
     ARRAY['customer_pii', 'video'], ARRAY['wazuh'], ARRAY['KISA-DB-01'],
     '2026-04-01 00:00:00+09', '2026-05-07 09:00:00+09', 'hash-data-001')

ON CONFLICT (asset_id) DO NOTHING;

-- 자산 ↔ 불변식
INSERT INTO asset_related_invariants (asset_id, invariant_id) VALUES
    ('APP-OPS-001',  'INV-STD-01'),
    ('APP-OPS-001',  'INV-STD-04'),
    ('APP-OPS-001',  'INV-STD-05'),
    ('APP-OPS-001',  'INV-STD-06'),
    ('APP-DMZ-001',  'INV-STD-08'),
    ('APP-DATA-001', 'INV-ARG-01')
ON CONFLICT DO NOTHING;


-- =============================================================================
-- GROUP 2. 서비스
-- =============================================================================

INSERT INTO services
    (service_id, name, owning_asset_id, vm, zone, component_type,
     log_source_refs, collected_by_wazuh, observation_status)
VALUES
    ('SVC-AUTH-001', 'Auth Service (JWT 발급/검증)',
     'APP-OPS-001', 'argos-ops', 'ops', 'application_api',
     ARRAY['/var/log/argos/auth.jsonl', '/var/log/argos/state/token_policy_state.jsonl'],
     TRUE, 'registered'),

    ('SVC-GW-001', 'API Gateway (Nginx)',
     'APP-DMZ-001', 'argos-dmz', 'dmz', 'gateway',
     ARRAY['/var/log/argos/gateway.jsonl', '/var/log/argos/state/network_policy_state.jsonl'],
     TRUE, 'registered'),

    ('SVC-DB-001', 'Customer Data DB (PostgreSQL)',
     'APP-DATA-001', 'argos-data', 'db', 'database',
     ARRAY['/var/log/argos/db.jsonl'],
     FALSE, 'registered')

ON CONFLICT (service_id) DO NOTHING;

-- 자산 ↔ 서비스
INSERT INTO asset_services (asset_id, service_id, relationship_type) VALUES
    ('APP-OPS-001',  'SVC-AUTH-001', 'linked'),
    ('APP-DMZ-001',  'SVC-GW-001',   'linked'),
    ('APP-DATA-001', 'SVC-DB-001',   'linked')
ON CONFLICT DO NOTHING;


-- =============================================================================
-- GROUP 3. 스캔
-- =============================================================================

INSERT INTO scans
    (scan_id, snapshot_id, scanned_at, status, score,
     total_violations, critical_high, attack_chains_count, asset_count, service_count)
VALUES
    ('SCAN-20260506-001', 'asset-snapshot-20260506090000',
     '2026-05-06 09:00:00+09', 'completed', 45, 3, 3, 2, 3, 3),
    ('SCAN-20260507-001', 'asset-snapshot-20260507090000',
     '2026-05-07 09:00:00+09', 'completed', 38, 3, 3, 2, 3, 3)
ON CONFLICT (scan_id) DO UPDATE SET
    status              = EXCLUDED.status,
    score               = EXCLUDED.score,
    total_violations    = EXCLUDED.total_violations,
    critical_high       = EXCLUDED.critical_high,
    attack_chains_count = EXCLUDED.attack_chains_count,
    asset_count         = EXCLUDED.asset_count,
    service_count       = EXCLUDED.service_count;

-- 스캔별 자산 스냅샷
INSERT INTO scan_asset_snapshot
    (scan_id, total, registered, unregistered, with_violation, online, offline,
     server_count, endpoint_count, iot_count, network_count)
VALUES
    ('SCAN-20260506-001', 3, 3, 0, 3, 3, 0, 2, 0, 0, 1),
    ('SCAN-20260507-001', 3, 3, 0, 3, 3, 0, 2, 0, 0, 1)
ON CONFLICT (scan_id) DO NOTHING;

-- Evidence 수집 현황
INSERT INTO evidence_type_coverage
    (scan_id, evidence_type, expected_in_final, collected_count, collection_status)
VALUES
    ('SCAN-20260506-001', 'account_state_event',     TRUE, 2, 'collected'),
    ('SCAN-20260506-001', 'api_authorization_event', TRUE, 5, 'collected'),
    ('SCAN-20260506-001', 'key_management_state',    TRUE, 1, 'collected'),
    ('SCAN-20260507-001', 'token_policy_state',      TRUE, 1, 'collected'),
    ('SCAN-20260507-001', 'gateway_access_event',    TRUE, 3, 'collected'),
    ('SCAN-20260507-001', 'data_access_event',       TRUE, 4, 'collected')
ON CONFLICT DO NOTHING;


-- =============================================================================
-- GROUP 4. Evidence Events (2026-05 파티션)
--
-- SCAN-20260506-001 공격 실행 흐름 (trace_id: trc-attack-20260506-001)
--   evd-s1-account-state-001: account_state_event  — 퇴직자 exuser1 계정 활성 상태 (P1)
--   evd-s1-api-authz-001:     api_authorization_event — 위조 토큰으로 /internal/api 접근 (P0)
--   evd-s1-data-access-001:   data_access_event    — tenant_b 데이터 조회 성공 (P0)
--
-- SCAN-20260507-001 환경 상태 점검 (trace_id: state-scan-20260507-001)
--   evd-s1-key-state-001:     key_management_state — 서명키 미회전 상태 (P1)
--   evd-s1-token-policy-001:  token_policy_state   — 검증 정책 미흡 상태 (P1)
--   evd-s1-gateway-access-001: gateway_access_event — DMZ 내부 API 외부 노출 / 2차 공격 (P0)
-- =============================================================================

INSERT INTO evidence_events
    (evidence_id, timestamp, schema_version, trace_id, request_id,
     event_category, evidence_type,
     producer_vm, producer_component_id, producer_component_type, producer_zone,
     producer_asset_id, producer_service_id,
     actor_id, actor_role, actor_source_ip_class,
     token_present, token_sub, token_tenant, token_kid, token_jti,
     token_signature_valid, token_issued_by_auth_server, token_revoked,
     access_action, access_endpoint, access_method, access_decision, access_status_code,
     target_asset_id, target_asset_type, target_asset_owner_id, target_asset_tenant_id,
     control_owner_check_performed, control_tenant_check_performed, control_authz_service_used,
     raw_ref_source, raw_ref_agent, raw_ref_location, raw_ref_log_id,
     observed)
VALUES
-- ── evd-s1-account-state-001: 퇴직자 계정 상태 (environment_state / P1) ─────────
(
    'evd-s1-account-state-001', '2026-05-06 08:00:00+09', 'argos-siem-event-v1',
    'state-scan-20260506-001', 'state-scan-20260506-001',
    'environment_state', 'account_state_event',
    'argos-mgmt', 'argos-account-state-collector', 'state_collector', 'mgmt',
    'APP-OPS-001', 'SVC-AUTH-001',
    'exuser1', 'former_auth_developer', 'internal',
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL,
    'wazuh', 'argos-mgmt', '/var/log/argos/state/account_state.jsonl', 'wazuh-account-state-001',
    '{
        "account_id": "exuser1",
        "employment_status": "retired",
        "account_status": "active",
        "credential_status": "active",
        "active_session_count": 1,
        "api_key_status": "active",
        "service_token_status": "active",
        "role": "former_auth_developer",
        "groups": ["Terminated"],
        "had_jwt_key_access": true
    }'::jsonb
),

-- ── evd-s1-api-authz-001: 위조 토큰으로 내부 API 접근 (attack_execution / P0) ────
(
    'evd-s1-api-authz-001', '2026-05-06 14:01:00+09', 'argos-siem-event-v1',
    'trc-attack-20260506-001', 'req-s1-001',
    'attack_execution', 'api_authorization_event',
    'argos-ops', 'argos-ops-api', 'api', 'ops',
    'APP-OPS-001', 'SVC-AUTH-001',
    'exuser1', 'former_auth_developer', 'external',
    TRUE, 'exuser1', 'tenant-a', 'kid-old-2025', 'jti-forged-001',
    TRUE, FALSE, FALSE,
    'ACCESS', '/internal/api/user-detail', 'GET', 'allow', 200,
    'APP-DATA-001', 'customer_profile', 'customer_b', 'tenant-b',
    FALSE, FALSE, FALSE,
    'wazuh', 'argos-ops', '/var/log/argos/api_authorization.jsonl', 'wazuh-api-authz-001',
    '{
        "token_jti": "jti-forged-001",
        "token_kid": "kid-old-2025",
        "signature_valid": true,
        "issued_by_auth_server": false,
        "kid_active": true,
        "revoked": false,
        "expired": false,
        "endpoint": "/internal/api/user-detail",
        "method": "GET",
        "target_identifier": "10000002",
        "resource_type": "customer_profile",
        "resource_id": "user-10000002",
        "resource_owner_id": "customer_b",
        "resource_tenant_id": "tenant-b",
        "owner_check_performed": false,
        "tenant_check_performed": false,
        "authz_service_used": false,
        "authorization_decision": "allow",
        "status_code": 200,
        "page_size": 1000,
        "bulk_export": false,
        "response_fields": ["name", "email", "phone", "address", "install_location"],
        "contains_address": true,
        "contains_install_location": true,
        "contains_door_access_info": false,
        "contains_video_access_url": false,
        "contains_thumbnail_url": false,
        "contains_object_key": false,
        "contains_sensor_log": false,
        "ticket_id": null,
        "access_reason": null,
        "audit_log_created": true
    }'::jsonb
),

-- ── evd-s1-data-access-001: tenant_b 데이터 조회 성공 (attack_execution / P0) ────
(
    'evd-s1-data-access-001', '2026-05-06 14:02:00+09', 'argos-siem-event-v1',
    'trc-attack-20260506-001', 'req-s1-001',
    'attack_execution', 'data_access_event',
    'argos-data', 'argos-postgresql', 'database', 'db',
    'APP-DATA-001', 'SVC-DB-001',
    'exuser1', 'former_auth_developer', 'internal',
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL,
    'QUERY', '/db/customer_profiles', 'POST', 'allow', 200,
    'APP-DATA-001', 'customer_profile', 'customer_b', 'tenant-b',
    FALSE, FALSE, FALSE,
    'wazuh', 'argos-data', '/var/log/argos/db.jsonl', 'wazuh-data-access-001',
    '{
        "db_user": "argos_app",
        "query_type": "SELECT",
        "table_name": "customer_profiles",
        "resource_type": "customer_profile",
        "resource_id": "user-10000002",
        "resource_owner_id": "customer_b",
        "resource_tenant_id": "tenant-b",
        "record_count": 1,
        "query_result": "success",
        "sensitive_field_types": ["name", "email", "phone", "address", "install_location"],
        "data_returned": true,
        "pii_value_included": false
    }'::jsonb
),

-- ── evd-s1-key-state-001: JWT 서명키 미회전 상태 (environment_state / P1) ─────────
(
    'evd-s1-key-state-001', '2026-05-07 08:00:00+09', 'argos-siem-event-v1',
    'state-scan-20260507-001', 'state-scan-20260507-001',
    'environment_state', 'key_management_state',
    'argos-ops', 'argos-key-state-collector', 'state_collector', 'ops',
    'APP-OPS-001', 'SVC-AUTH-001',
    NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL,
    'wazuh', 'argos-ops', '/var/log/argos/state/key_management_state.jsonl', 'wazuh-key-state-001',
    '{
        "key_id": "jwt-key-2025-old",
        "key_type": "jwt_signing_key",
        "key_status": "active",
        "storage_location_type": ".env",
        "stored_in_approved_secret_manager": false,
        "retired_user_had_access": true,
        "last_rotated_at": "2025-01-10T09:00:00+09:00",
        "previous_key_status": "active",
        "key_rotation_required": true,
        "key_rotation_completed": false
    }'::jsonb
),

-- ── evd-s1-token-policy-001: 토큰 검증 정책 미흡 상태 (environment_state / P1) ────
(
    'evd-s1-token-policy-001', '2026-05-07 08:05:00+09', 'argos-siem-event-v1',
    'state-scan-20260507-001', 'state-scan-20260507-001',
    'environment_state', 'token_policy_state',
    'argos-ops', 'argos-token-policy-collector', 'state_collector', 'ops',
    'APP-OPS-001', 'SVC-AUTH-001',
    NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL,
    'wazuh', 'argos-ops', '/var/log/argos/state/token_policy_state.jsonl', 'wazuh-token-policy-001',
    '{
        "validate_signature": true,
        "validate_issuer": false,
        "validate_audience": false,
        "validate_expiration": true,
        "validate_iat": false,
        "validate_kid_active": false,
        "validate_jti_registry": false,
        "validate_revocation": false,
        "token_registry_enabled": false,
        "revocation_list_enabled": false
    }'::jsonb
),

-- ── evd-s1-gateway-access-001: 2차 공격 — DMZ 내부 API 외부 노출 (attack_execution / P0)
(
    'evd-s1-gateway-access-001', '2026-05-07 14:01:00+09', 'argos-siem-event-v1',
    'trc-attack-20260507-001', 'req-s1-101',
    'attack_execution', 'gateway_access_event',
    'argos-dmz', 'argos-dmz-nginx', 'gateway', 'dmz',
    'APP-DMZ-001', 'SVC-GW-001',
    'exuser1', 'former_auth_developer', 'external',
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL,
    'ACCESS', '/internal/api/user-detail', 'GET', 'allow', 200,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL,
    'wazuh', 'argos-dmz', '/var/log/argos/gateway.jsonl', 'wazuh-gateway-access-001',
    '{
        "source_ip": "203.0.113.10",
        "source_zone": "internet",
        "destination_zone": "ops",
        "method": "GET",
        "uri": "/internal/api/user-detail?userId=10000002",
        "normalized_endpoint": "/internal/api/user-detail",
        "endpoint_group": "/internal",
        "internal_path_requested": true,
        "forwarded_to": "argos-ops",
        "status_code": 200,
        "allowed_path": false,
        "waf_action": "allow",
        "rate_limited": false,
        "vpn_user": null,
        "external_access_to_internal_api_allowed": true,
        "default_internal_path_action": "allow",
        "allowed_source_zones": ["ops", "mgmt"],
        "rate_limit_policy_enabled": false
    }'::jsonb
)

ON CONFLICT DO NOTHING;


-- =============================================================================
-- GROUP 5. Violations (AI1 결과)
-- =============================================================================

INSERT INTO violations
    (result_id, scan_id, invariant_id, status, violation_reason,
     summary, reason, confidence, current_environment_testable, testability_reason, created_at)
VALUES
-- SCAN-20260506-001: 공격 실행 단계에서 포착된 위반 3건
    ('ai1-s1-inv-std-01-001', 'SCAN-20260506-001', 'INV-STD-01', 'violated', 'clear_violation',
     '퇴직자 계정 exuser1이 퇴직 후에도 active 상태로 로그인 활동 확인됨',
     'account_state_event에서 employment_status=retired, account_status=active, had_jwt_key_access=true 확인. 활성 세션 및 서비스 토큰도 유지 중.',
     0.97, TRUE, 'account_state_event로 재현 가능',
     '2026-05-06 09:30:00+09'),

    ('ai1-s1-inv-std-05-001', 'SCAN-20260506-001', 'INV-STD-05', 'violated', 'clear_violation',
     '외부에서 발급된 위조 JWT 토큰(issued_by_auth_server=false)으로 /internal/api 접근 성공',
     'api_authorization_event에서 signature_valid=true이나 issued_by_auth_server=false 확인. 인증 서버 발급 여부 검증 없이 200 응답 반환.',
     0.95, TRUE, '위조 토큰 발급 후 API 호출로 재현 가능',
     '2026-05-06 09:30:00+09'),

    ('ai1-s1-inv-arg-01-001', 'SCAN-20260506-001', 'INV-ARG-01', 'violated', 'clear_violation',
     'tenant_a 계정(exuser1)이 tenant_b 고객 데이터에 접근 성공 — 테넌트 격리 완전 실패',
     'api_authorization_event에서 token_tenant=tenant-a, resource_tenant_id=tenant-b, tenant_check_performed=false 확인. data_access_event에서 실제 조회 성공 확인.',
     0.99, TRUE, 'tenant_a 계정으로 /internal/api 호출 시 재현 가능',
     '2026-05-06 09:30:00+09'),

-- SCAN-20260507-001: 근본 원인 환경 상태에서 포착된 위반 3건
    ('ai1-s1-inv-std-04-001', 'SCAN-20260507-001', 'INV-STD-04', 'violated', 'clear_violation',
     'JWT 서명키 jwt-key-2025-old가 퇴직자 접근 이후 480일간 미회전 상태',
     'key_management_state에서 retired_user_had_access=true, last_rotated_at=2025-01-10, key_rotation_completed=false 확인. 서명키가 .env에 평문 저장.',
     0.99, FALSE, '운영 환경 키 관리 시스템 접근 필요',
     '2026-05-07 09:30:00+09'),

    ('ai1-s1-inv-std-06-001', 'SCAN-20260507-001', 'INV-STD-06', 'violated', 'clear_violation',
     'JWT 토큰 검증 정책에서 issuer·kid·jti·revocation 검증이 모두 비활성화 상태',
     'token_policy_state에서 validate_issuer=false, validate_kid_active=false, validate_jti_registry=false, validate_revocation=false 확인. 서명 검증만 수행하여 외부 발급 위조 토큰 탐지 불가.',
     0.98, TRUE, 'token_policy_state 조회로 즉시 확인 가능',
     '2026-05-07 09:30:00+09'),

    ('ai1-s1-inv-std-08-001', 'SCAN-20260507-001', 'INV-STD-08', 'violated', 'clear_violation',
     'DMZ 게이트웨이에서 /internal/* 경로가 외부(internet) 접근에 허용되어 있음',
     'gateway_access_event에서 source_zone=internet, internal_path_requested=true, allowed_path=false임에도 waf_action=allow, status_code=200 확인. external_access_to_internal_api_allowed=true 정책 확인.',
     0.96, TRUE, '외부에서 /internal/* 경로 직접 호출로 재현 가능',
     '2026-05-07 09:30:00+09')

ON CONFLICT (result_id) DO NOTHING;

-- violation ↔ evidence
INSERT INTO violation_evidence (violation_id, evidence_id) VALUES
    ('ai1-s1-inv-std-01-001', 'evd-s1-account-state-001'),
    ('ai1-s1-inv-std-05-001', 'evd-s1-api-authz-001'),
    ('ai1-s1-inv-arg-01-001', 'evd-s1-api-authz-001'),
    ('ai1-s1-inv-arg-01-001', 'evd-s1-data-access-001'),
    ('ai1-s1-inv-std-04-001', 'evd-s1-key-state-001'),
    ('ai1-s1-inv-std-06-001', 'evd-s1-token-policy-001'),
    ('ai1-s1-inv-std-08-001', 'evd-s1-gateway-access-001')
ON CONFLICT DO NOTHING;

-- violation ↔ assets
INSERT INTO violation_assets (violation_id, asset_id) VALUES
    ('ai1-s1-inv-std-01-001', 'APP-OPS-001'),
    ('ai1-s1-inv-std-05-001', 'APP-OPS-001'),
    ('ai1-s1-inv-std-05-001', 'APP-DMZ-001'),
    ('ai1-s1-inv-arg-01-001', 'APP-DATA-001'),
    ('ai1-s1-inv-std-04-001', 'APP-OPS-001'),
    ('ai1-s1-inv-std-06-001', 'APP-OPS-001'),
    ('ai1-s1-inv-std-08-001', 'APP-DMZ-001')
ON CONFLICT DO NOTHING;


-- =============================================================================
-- GROUP 6. Attack Chains (AI2 결과)
-- =============================================================================

INSERT INTO attack_chains
    (chain_scenario_id, scan_id, created_at, title, source_bundle_id, risk_level,
     scenario_basis_status, scenario_basis_violation_reason, scenario_basis_summary,
     current_environment_testable, testability_reason)
VALUES
    ('chain-s1-retired-account-forged-jwt-tenant-breach-001',
     'SCAN-20260506-001', '2026-05-06 10:00:00+09',
     '퇴직자 계정 → 위조 JWT → 테넌트 격리 위반 → 고객 PII 탈취',
     'bundle-s1-retired-account-forged-jwt-tenant-breach-001', 'critical',
     'violated', 'clear_violation',
     'INV-STD-01·STD-05·ARG-01 연쇄 위반. 퇴직자 서명키로 위조 토큰 생성 후 tenant 격리 미적용 API를 통해 전체 테넌트 고객 데이터 탈취 가능.',
     TRUE, '각 단계 개별 재현 가능, 전체 체인 30분 내 재현'),

    ('chain-s1-dmz-exposure-token-bypass-001',
     'SCAN-20260506-001', '2026-05-06 10:00:00+09',
     'DMZ 내부 API 노출 → 외부 발급 토큰 통과 → 무단 데이터 조회',
     'bundle-s1-dmz-exposure-token-bypass-001', 'high',
     'violated', 'clear_violation',
     'INV-STD-05·STD-08 복합 취약점. DMZ 게이트웨이가 /internal/* 경로를 차단하지 않고(STD-08), 토큰 검증 정책 미흡(STD-05)으로 외부 발급 위조 토큰이 통과. 두 조건이 SCAN-20260506-001 공격에서 동시 동작함을 확인.',
     TRUE, '외부 IP에서 /internal/* 직접 호출로 재현 가능'),

    ('chain-s1-key-rotation-failure-persistent-access-001',
     'SCAN-20260507-001', '2026-05-07 10:00:00+09',
     'JWT 서명키 미회전 → 위조 토큰 지속 유효 → 장기 잠복 공격 가능',
     'bundle-s1-key-rotation-failure-persistent-access-001', 'critical',
     'violated', 'clear_violation',
     'INV-STD-04·STD-06 연쇄 위반. 서명키 미회전으로 퇴직자가 생성한 위조 토큰이 계속 유효. 검증 정책도 미흡하여 탐지 불가.',
     FALSE, '운영 환경 서명키 접근 필요, 테스트 환경 별도 구성 필요'),

    ('chain-s1-dmz-policy-token-validation-bypass-001',
     'SCAN-20260507-001', '2026-05-07 10:00:00+09',
     'DMZ 정책 미흡 + 토큰 검증 부재 → 인증 체계 전면 우회 가능',
     'bundle-s1-dmz-policy-token-validation-bypass-001', 'critical',
     'violated', 'clear_violation',
     'INV-STD-06·STD-08 연쇄 위반. 외부 → DMZ → 내부 API 경로가 열려 있고 토큰 발급처 검증도 없어 어떤 외부 발급 토큰도 허용됨.',
     TRUE, 'curl로 외부에서 /internal/* 호출 시 재현 가능')

ON CONFLICT (chain_scenario_id) DO NOTHING;

-- 공격 체인 ↔ 불변식
INSERT INTO attack_chain_invariants (chain_id, invariant_id) VALUES
    ('chain-s1-retired-account-forged-jwt-tenant-breach-001', 'INV-STD-01'),
    ('chain-s1-retired-account-forged-jwt-tenant-breach-001', 'INV-STD-05'),
    ('chain-s1-retired-account-forged-jwt-tenant-breach-001', 'INV-ARG-01'),
    ('chain-s1-dmz-exposure-token-bypass-001',                'INV-STD-05'),
    ('chain-s1-key-rotation-failure-persistent-access-001',   'INV-STD-04'),
    ('chain-s1-key-rotation-failure-persistent-access-001',   'INV-STD-06'),
    ('chain-s1-dmz-policy-token-validation-bypass-001',       'INV-STD-06'),
    ('chain-s1-dmz-policy-token-validation-bypass-001',       'INV-STD-08')
ON CONFLICT DO NOTHING;

-- 공격 체인 단계
INSERT INTO attack_chain_steps (chain_id, step_order, step_text) VALUES
    ('chain-s1-retired-account-forged-jwt-tenant-breach-001', 1, '퇴직자 exuser1이 접근한 서명키 jwt-key-2025-old로 위조 JWT 토큰 생성'),
    ('chain-s1-retired-account-forged-jwt-tenant-breach-001', 2, 'argos-dmz 게이트웨이 통과 (내부 API 외부 노출, WAF 미차단)'),
    ('chain-s1-retired-account-forged-jwt-tenant-breach-001', 3, 'argos-ops /internal/api/user-detail 호출 — tenant 검증 없이 200 응답'),
    ('chain-s1-retired-account-forged-jwt-tenant-breach-001', 4, 'tenant_b 고객 PII (이름·이메일·전화·주소·설치 위치) 대량 탈취'),

    ('chain-s1-dmz-exposure-token-bypass-001', 1, '외부 IP에서 /internal/api/* 경로 직접 요청'),
    ('chain-s1-dmz-exposure-token-bypass-001', 2, 'DMZ 게이트웨이 allowed_path=false이나 waf_action=allow로 통과'),
    ('chain-s1-dmz-exposure-token-bypass-001', 3, '외부 발급 토큰 issuer/kid 검증 없이 그대로 허용 — 200 응답'),

    ('chain-s1-key-rotation-failure-persistent-access-001', 1, '서명키 jwt-key-2025-old가 480일째 미회전 상태 유지'),
    ('chain-s1-key-rotation-failure-persistent-access-001', 2, '퇴직자가 .env에서 확보한 키로 언제든 위조 토큰 생성 가능'),
    ('chain-s1-key-rotation-failure-persistent-access-001', 3, '토큰 검증 정책(issuer/kid/jti 미검증)으로 위조 토큰 탐지 불가'),

    ('chain-s1-dmz-policy-token-validation-bypass-001', 1, 'DMZ에서 /internal/* 경로 외부 허용 정책 확인'),
    ('chain-s1-dmz-policy-token-validation-bypass-001', 2, '토큰 발급처(issuer) 및 kid 활성 여부 검증 비활성화 확인'),
    ('chain-s1-dmz-policy-token-validation-bypass-001', 3, '두 취약점 결합 시 어떤 자체 서명 JWT로도 내부 API 접근 가능')

ON CONFLICT DO NOTHING;

-- MITRE ATT&CK 흐름
INSERT INTO mitre_attack_flow (chain_id, flow_order, tactic, technique, step, reason) VALUES
    ('chain-s1-retired-account-forged-jwt-tenant-breach-001', 1, 'TA0001', 'T1078.001', '유효 계정 악용 — 퇴직자 계정 자격증명 재사용',
     'exuser1 계정 비활성화 미적용, 서비스 토큰 미회수'),
    ('chain-s1-retired-account-forged-jwt-tenant-breach-001', 2, 'TA0005', 'T1550.001', '위조 JWT 토큰으로 인증 우회',
     'jwt-key-2025-old 미회전, issuer/kid 검증 미적용'),
    ('chain-s1-retired-account-forged-jwt-tenant-breach-001', 3, 'TA0009', 'T1213',     '내부 API를 통한 데이터 수집',
     '테넌트 격리 미적용으로 타 테넌트 데이터 접근 가능'),
    ('chain-s1-retired-account-forged-jwt-tenant-breach-001', 4, 'TA0010', 'T1530',     '고객 PII 데이터 탈취',
     'owner/tenant 검증 없이 customer_profiles 대량 조회 성공'),

    ('chain-s1-dmz-exposure-token-bypass-001', 1, 'TA0001', 'T1190',     'DMZ 노출된 내부 API 경로로 초기 접근',
     '/internal/* 경로 WAF 미차단'),
    ('chain-s1-dmz-exposure-token-bypass-001', 2, 'TA0005', 'T1550.001', '외부 발급 토큰 재사용으로 인증 통과',
     'issued_by_auth_server 검증 없음'),
    ('chain-s1-dmz-exposure-token-bypass-001', 3, 'TA0009', 'T1213',     '내부 API 무단 접근 후 데이터 수집',
     'authz_service_used=false, tenant_check_performed=false'),

    ('chain-s1-key-rotation-failure-persistent-access-001', 1, 'TA0003', 'T1098',     '서명키 미교체로 지속 접근 수단 유지',
     'key_rotation_completed=false, retired_user_had_access=true'),
    ('chain-s1-key-rotation-failure-persistent-access-001', 2, 'TA0005', 'T1600',     'JWT 서명키 악용으로 토큰 위조',
     'stored_in_approved_secret_manager=false, .env 평문 저장'),
    ('chain-s1-key-rotation-failure-persistent-access-001', 3, 'TA0005', 'T1550.001', '검증 정책 미흡으로 위조 토큰 지속 유효',
     'validate_kid_active=false, validate_jti_registry=false'),

    ('chain-s1-dmz-policy-token-validation-bypass-001', 1, 'TA0001', 'T1190',     'DMZ 게이트웨이 /internal/* 외부 허용으로 초기 접근',
     'external_access_to_internal_api_allowed=true, default_internal_path_action=allow'),
    ('chain-s1-dmz-policy-token-validation-bypass-001', 2, 'TA0005', 'T1550.001', '토큰 발급처·kid 검증 부재로 인증 체계 우회',
     'validate_issuer=false, validate_kid_active=false'),
    ('chain-s1-dmz-policy-token-validation-bypass-001', 3, 'TA0006', 'T1562.001', 'DMZ 차단 없음·검증 정책 미흡 결합 — 어떤 자체 서명 JWT도 허용',
     'rate_limit_policy_enabled=false, 두 취약점 결합으로 방어 체계 전면 무력화')

ON CONFLICT DO NOTHING;

-- MITRE 흐름 ↔ 불변식
INSERT INTO mitre_flow_invariants (flow_id, invariant_id)
    SELECT id, 'INV-STD-01' FROM mitre_attack_flow
    WHERE chain_id = 'chain-s1-retired-account-forged-jwt-tenant-breach-001' AND flow_order = 1
ON CONFLICT DO NOTHING;

INSERT INTO mitre_flow_invariants (flow_id, invariant_id)
    SELECT id, 'INV-STD-05' FROM mitre_attack_flow
    WHERE chain_id = 'chain-s1-retired-account-forged-jwt-tenant-breach-001' AND flow_order = 2
ON CONFLICT DO NOTHING;

INSERT INTO mitre_flow_invariants (flow_id, invariant_id)
    SELECT id, 'INV-ARG-01' FROM mitre_attack_flow
    WHERE chain_id = 'chain-s1-retired-account-forged-jwt-tenant-breach-001' AND flow_order = 3
ON CONFLICT DO NOTHING;

INSERT INTO mitre_flow_invariants (flow_id, invariant_id)
    SELECT id, 'INV-ARG-01' FROM mitre_attack_flow
    WHERE chain_id = 'chain-s1-retired-account-forged-jwt-tenant-breach-001' AND flow_order = 4
ON CONFLICT DO NOTHING;

INSERT INTO mitre_flow_invariants (flow_id, invariant_id)
    SELECT id, 'INV-STD-05' FROM mitre_attack_flow
    WHERE chain_id = 'chain-s1-dmz-exposure-token-bypass-001' AND flow_order = 2
ON CONFLICT DO NOTHING;

INSERT INTO mitre_flow_invariants (flow_id, invariant_id)
    SELECT id, 'INV-STD-04' FROM mitre_attack_flow
    WHERE chain_id = 'chain-s1-key-rotation-failure-persistent-access-001' AND flow_order = 1
ON CONFLICT DO NOTHING;

INSERT INTO mitre_flow_invariants (flow_id, invariant_id)
    SELECT id, 'INV-STD-04' FROM mitre_attack_flow
    WHERE chain_id = 'chain-s1-key-rotation-failure-persistent-access-001' AND flow_order = 2
ON CONFLICT DO NOTHING;

INSERT INTO mitre_flow_invariants (flow_id, invariant_id)
    SELECT id, 'INV-STD-06' FROM mitre_attack_flow
    WHERE chain_id = 'chain-s1-key-rotation-failure-persistent-access-001' AND flow_order = 3
ON CONFLICT DO NOTHING;

INSERT INTO mitre_flow_invariants (flow_id, invariant_id)
    SELECT id, 'INV-STD-08' FROM mitre_attack_flow
    WHERE chain_id = 'chain-s1-dmz-policy-token-validation-bypass-001' AND flow_order = 1
ON CONFLICT DO NOTHING;

INSERT INTO mitre_flow_invariants (flow_id, invariant_id)
    SELECT id, 'INV-STD-06' FROM mitre_attack_flow
    WHERE chain_id = 'chain-s1-dmz-policy-token-validation-bypass-001' AND flow_order = 2
ON CONFLICT DO NOTHING;

-- 수동 검증 가이드 (4개 체인)
INSERT INTO validation_guide
    (chain_id, goal, steps, success_criteria, evidence_to_collect, safety_boundary)
VALUES
(
    'chain-s1-retired-account-forged-jwt-tenant-breach-001',
    '퇴직자 서명키 → 위조 토큰 → 테넌트 격리 위반 전체 공격 체인 재현',
    '[
        {"order":1,"text":"exuser1 계정으로 jwt-key-2025-old 서명으로 JWT 토큰 직접 생성"},
        {"order":2,"text":"생성된 토큰으로 argos-dmz를 통해 /internal/api/user-detail 호출"},
        {"order":3,"text":"token_tenant=tenant-a로 tenant-b 소유 userId 조회"},
        {"order":4,"text":"200 응답 및 PII 데이터 반환 확인"}
    ]'::jsonb,
    '["위조 토큰 생성 성공","DMZ 게이트웨이 통과 확인","타 테넌트 데이터 200 응답 반환","PII 필드(이름·이메일·주소) 포함 확인"]'::jsonb,
    '["argos-ops api_authorization_event 로그","argos-dmz gateway_access_event 로그","argos-data data_access_event 로그","account_state_event (exuser1 상태)","key_management_state (jwt-key-2025-old 상태)"]'::jsonb,
    '["실제 고객 데이터 조회 금지 — 테스트 계정 사용","테스트 완료 후 생성한 위조 토큰 즉시 폐기","서명키 원문 절대 외부 공개 금지"]'::jsonb
),
(
    'chain-s1-dmz-exposure-token-bypass-001',
    'DMZ /internal/* 외부 노출 + 토큰 검증 부재 결합 취약점 재현',
    '[
        {"order":1,"text":"외부 IP에서 curl로 /internal/api/* 직접 호출"},
        {"order":2,"text":"DMZ waf_action 로그 확인 — allowed_path=false임에도 allow 처리 확인"},
        {"order":3,"text":"외부 발급 자체 서명 JWT 토큰 생성 후 Authorization 헤더에 포함"},
        {"order":4,"text":"200 응답 여부 확인"}
    ]'::jsonb,
    '["외부에서 /internal/* 200 응답 확인","WAF allowed_path=false 상태에서 통과 로그 확인","외부 발급 토큰 허용 확인"]'::jsonb,
    '["argos-dmz gateway_access_event 로그","argos-ops api_authorization_event","token_policy_state (issuer 검증 비활성 확인)"]'::jsonb,
    '["실제 데이터 접근 금지 — 테스트 엔드포인트 사용","테스트 후 임시 방화벽 규칙 원복"]'::jsonb
),
(
    'chain-s1-key-rotation-failure-persistent-access-001',
    'JWT 서명키 미회전 상태에서 위조 토큰 발급 및 탐지 불가 재현',
    '[
        {"order":1,"text":"key_management_state에서 jwt-key-2025-old 회전 여부 확인"},
        {"order":2,"text":"해당 키로 임의 JWT 토큰 생성 (테스트 환경에서)"},
        {"order":3,"text":"token_policy_state에서 validate_kid_active=false 확인"},
        {"order":4,"text":"생성한 토큰이 서버에서 유효하게 처리되는지 확인"}
    ]'::jsonb,
    '["key_rotation_completed=false 확인","위조 토큰 생성 성공 (테스트 환경)","서버에서 위조 토큰 유효 처리 확인","validate_kid_active=false 정책 확인"]'::jsonb,
    '["key_management_state (jwt-key-2025-old)","token_policy_state (validate_kid_active 항목)","api_authorization_event (토큰 처리 결과)"]'::jsonb,
    '["운영 서명키 원문 절대 사용 금지 — 별도 테스트 키 사용","테스트 환경 격리 필수","테스트 후 생성 토큰 즉시 폐기"]'::jsonb
),
(
    'chain-s1-dmz-policy-token-validation-bypass-001',
    'DMZ 정책 미흡 + 토큰 검증 부재 결합 취약점 재현',
    '[
        {"order":1,"text":"외부 IP에서 curl로 /internal/api/* 직접 호출"},
        {"order":2,"text":"자체 서명된 임의 JWT 토큰 생성 후 Authorization 헤더에 포함"},
        {"order":3,"text":"200 응답 여부 확인"}
    ]'::jsonb,
    '["외부에서 /internal/* 200 응답 확인","임의 JWT 토큰 통과 확인","waf_action=allow 로그 확인"]'::jsonb,
    '["argos-dmz gateway_access_event 로그","argos-ops token_policy_state","argos-ops api_authorization_event"]'::jsonb,
    '["실 데이터 접근 금지","테스트 전용 엔드포인트 사용 권장","테스트 종료 후 임시 규칙 원복"]'::jsonb
)
ON CONFLICT (chain_id) DO NOTHING;


-- =============================================================================
-- GROUP 7. Red Team 결과
-- =============================================================================

INSERT INTO pentest_results
    (test_id, schema_version, scan_id, scenario_id, tester, tested_at, overall_verdict,
     attack_input_and_process, observed_result, impact_assessment,
     evidence_description, additional_notes)
VALUES
(
    'rt-20260506-001', 'argos-redteam-result-v3',
    'SCAN-20260506-001', 'chain-s1-retired-account-forged-jwt-tenant-breach-001',
    '김철수', '2026-05-06 14:00:00+09', 'reproduced',
    'exuser1 계정으로 jwt-key-2025-old 서명 위조 토큰 생성. argos-dmz 경유 /internal/api/user-detail?userId=10000002 호출.',
    'token_tenant=tenant-a 상태로 tenant-b 소유 userId 200 응답. name·email·phone·address·install_location 반환 확인.',
    '실 운영 환경에서 전체 테넌트 고객 PII 탈취 가능. GDPR/개인정보보호법 위반 해당. 즉각 키 교체 및 계정 비활성화 필요.',
    'api_authorization_event(wazuh-api-authz-001), data_access_event(wazuh-data-access-001) 로그 캡처 완료.',
    '전체 체인 25분 내 재현 완료. 퇴직 480일 경과 계정 및 키 상태 그대로 유지 중 확인.'
),
(
    'rt-20260506-002', 'argos-redteam-result-v3',
    'SCAN-20260506-001', 'chain-s1-dmz-exposure-token-bypass-001',
    '이영희', '2026-05-06 15:30:00+09', 'reproduced',
    '외부 IP(203.0.113.10)에서 /internal/api/* 직접 호출. 별도 VPN 없이 curl 사용.',
    'DMZ 게이트웨이 통과 확인. WAF allowed_path=false 설정에도 waf_action=allow로 200 응답.',
    'DMZ 게이트웨이 설정 오류로 내부 API 전체 외부 노출. 토큰만 있으면 누구든 접근 가능.',
    'gateway_access_event(wazuh-gateway-access-001) 로그 캡처. 외부 접근 패킷 덤프 저장.',
    '/internal/* 경로 전체 외부 허용 상태. 즉각 차단 규칙 적용 권고.'
),
(
    'rt-20260506-003', 'argos-redteam-result-v3',
    'SCAN-20260506-001', 'chain-s1-retired-account-forged-jwt-tenant-breach-001',
    '박민준', '2026-05-06 16:00:00+09', 'reproduced',
    'tenant_a 계정으로 tenant_b·c·d 소유 userId 순차 조회. owner_check 및 tenant_check 미수행 확인.',
    '타 테넌트 데이터 조회 모두 성공. 전체 테넌트 데이터 접근 가능함을 확인.',
    '테넌트 격리 완전 실패. 서비스 전체 고객 데이터 노출 가능. 즉각 tenant_check 미들웨어 적용 필요.',
    'api_authorization_event, data_access_event 로그 다수 캡처.',
    '테넌트 격리 검증 코드 자체가 구현되어 있지 않음을 코드 레벨에서도 확인.'
),
(
    'rt-20260507-001', 'argos-redteam-result-v3',
    'SCAN-20260507-001', 'chain-s1-key-rotation-failure-persistent-access-001',
    '김철수', '2026-05-07 14:00:00+09', 'reproduced',
    'key_management_state에서 jwt-key-2025-old 상태 직접 조회. last_rotated_at 및 key_rotation_completed 확인.',
    '서명키가 .env에 평문 저장, 480일 미회전. key_rotation_required=true이나 key_rotation_completed=false.',
    '공격자가 .env에 접근할 수 있는 경우 위조 토큰 무한 생성 가능. 키 교체 전까지 지속 노출.',
    'key_management_state(wazuh-key-state-001) 로그 캡처. .env 파일 저장 위치 확인.',
    '키 교체 후 이전 키 폐기 및 revocation_list 도입 필요. approved_secret_manager 이관 권고.'
),
(
    'rt-20260507-002', 'argos-redteam-result-v3',
    'SCAN-20260507-001', 'chain-s1-dmz-policy-token-validation-bypass-001',
    '이영희', '2026-05-07 15:00:00+09', 'reproduced',
    'token_policy_state 직접 조회. validate_issuer·validate_kid_active·validate_jti_registry 모두 false 확인.',
    '임의 서명 알고리즘(HS256)으로 자체 서명한 JWT 토큰이 정상 처리됨.',
    '토큰 검증 정책이 사실상 서명 검증만 수행. 어떤 키로 서명해도 서버가 유효성 확인 불가.',
    'token_policy_state(wazuh-token-policy-001) 로그 캡처.',
    'validate_issuer·validate_kid_active·validate_jti_registry 즉시 활성화 권고.'
),
(
    'rt-20260507-003', 'argos-redteam-result-v3',
    'SCAN-20260507-001', 'chain-s1-dmz-policy-token-validation-bypass-001',
    '박민준', '2026-05-07 16:00:00+09', 'partially_reproduced',
    'DMZ network_policy_state 조회. external_access_to_internal_api_allowed=true 및 rate_limit_policy_enabled=false 확인.',
    'DMZ 정책 미흡은 확인됐으나 실제 대량 자동화 공격 재현은 rate_limit 부재로 이론상 가능.',
    '현재 rate limit 없어 자동화 스크립트로 전체 고객 데이터 순차 탈취 가능.',
    'gateway_access_event(wazuh-gateway-access-001) 및 network_policy_state 캡처.',
    'rate_limit_policy 즉시 도입 및 /internal/* 외부 차단 병행 권고.'
)

ON CONFLICT (test_id) DO NOTHING;

-- pentest ↔ 불변식
INSERT INTO pentest_related_invariants (test_id, invariant_id) VALUES
    ('rt-20260506-001', 'INV-STD-01'),
    ('rt-20260506-001', 'INV-STD-05'),
    ('rt-20260506-001', 'INV-ARG-01'),
    ('rt-20260506-002', 'INV-STD-05'),
    ('rt-20260506-002', 'INV-STD-08'),
    ('rt-20260506-003', 'INV-ARG-01'),
    ('rt-20260507-001', 'INV-STD-04'),
    ('rt-20260507-002', 'INV-STD-06'),
    ('rt-20260507-003', 'INV-STD-06'),
    ('rt-20260507-003', 'INV-STD-08')
ON CONFLICT DO NOTHING;

-- pentest ↔ assets
INSERT INTO pentest_target_assets (test_id, asset_id, asset_type) VALUES
    ('rt-20260506-001', 'APP-OPS-001',  'application_audit_log'),
    ('rt-20260506-001', 'APP-DATA-001', 'auth_service'),
    ('rt-20260506-002', 'APP-DMZ-001',  'network_device'),
    ('rt-20260506-003', 'APP-DATA-001', 'auth_service'),
    ('rt-20260507-001', 'APP-OPS-001',  'application_audit_log'),
    ('rt-20260507-002', 'APP-OPS-001',  'application_audit_log'),
    ('rt-20260507-003', 'APP-DMZ-001',  'network_device')
ON CONFLICT DO NOTHING;


-- =============================================================================
-- GROUP 8. 조치 항목
-- =============================================================================

INSERT INTO remediations (invariant_id, scan_id, description, attack_phase, priority, done)
VALUES
    ('INV-STD-01', 'SCAN-20260506-001',
     '퇴직자 계정 exuser1 즉시 비활성화. 전체 퇴직자 계정 전수 조사 후 IAM 연동 자동 비활성화 구축.',
     '자격증명', '즉시', FALSE),

    ('INV-STD-05', 'SCAN-20260506-001',
     'Auth Service에 issued_by_auth_server 검증 로직 추가. JTI registry 도입하여 정상 발급 토큰만 허용.',
     '초기침투', '즉시', FALSE),

    ('INV-ARG-01', 'SCAN-20260506-001',
     '모든 API 엔드포인트에 tenant_check 미들웨어 적용. Authz Service를 통한 테넌트 격리 의무화.',
     '데이터탈취', '즉시', FALSE),

    ('INV-STD-04', 'SCAN-20260507-001',
     'jwt-key-2025-old 즉시 교체 및 이전 키 폐기. 키 회전 자동화 구축 (90일 주기). approved_secret_manager 이관.',
     '자격증명', '즉시', FALSE),

    ('INV-STD-06', 'SCAN-20260507-001',
     'validate_issuer·validate_kid_active·validate_jti_registry·validate_revocation 정책 즉시 활성화. revocation_list 운영 시작.',
     '방어우회', '즉시', FALSE),

    ('INV-STD-08', 'SCAN-20260507-001',
     'DMZ 게이트웨이에서 /internal/* 경로 외부 접근 차단 규칙 즉시 적용. rate_limit_policy 도입. WAF 규칙 재검토.',
     '초기침투', '즉시', FALSE);


-- =============================================================================
-- GROUP 9. Invariant Impact (자산 영향 요약)
-- =============================================================================

INSERT INTO invariant_impact
    (invariant_id, result_id, scan_id, status, violation_reason, severity,
     summary, affected_resource_ids, affected_zones)
VALUES
    ('INV-STD-01', 'ai1-s1-inv-std-01-001', 'SCAN-20260506-001', 'violated', 'clear_violation', 'High',
     '퇴직자 계정 exuser1 활성 상태 — 서명키 접근 이력 있는 계정이 회수되지 않아 자격증명 탈취 경로 확보됨',
     ARRAY['exuser1'], ARRAY['ops', 'mgmt']),

    ('INV-STD-05', 'ai1-s1-inv-std-05-001', 'SCAN-20260506-001', 'violated', 'clear_violation', 'Critical',
     '외부 발급 위조 JWT로 내부 API 접근 성공 — 인증 서버 발급 여부 미검증으로 인증 체계 우회',
     ARRAY['user-10000002', 'customer_b'], ARRAY['ops', 'dmz']),

    ('INV-ARG-01', 'ai1-s1-inv-arg-01-001', 'SCAN-20260506-001', 'violated', 'clear_violation', 'Critical',
     'tenant_a 계정이 tenant_b 데이터 접근 — owner/tenant 검증 미적용으로 전체 테넌트 고객 데이터 노출',
     ARRAY['user-10000002', 'customer_b', 'tenant-b'], ARRAY['ops', 'db']),

    ('INV-STD-04', 'ai1-s1-inv-std-04-001', 'SCAN-20260507-001', 'violated', 'clear_violation', 'Critical',
     'jwt-key-2025-old 480일 미회전 — 퇴직자 접근 이후 서명키 미교체로 위조 토큰 발급 경로 지속 개방',
     ARRAY['jwt-key-2025-old'], ARRAY['ops']),

    ('INV-STD-06', 'ai1-s1-inv-std-06-001', 'SCAN-20260507-001', 'violated', 'clear_violation', 'High',
     'JWT 검증 정책 미흡 — issuer/kid/jti/revocation 미검증으로 외부 발급 위조 토큰 탐지 불가',
     ARRAY[]::TEXT[], ARRAY['ops']),

    ('INV-STD-08', 'ai1-s1-inv-std-08-001', 'SCAN-20260507-001', 'violated', 'clear_violation', 'Critical',
     'DMZ /internal/* 외부 노출 — WAF 차단 정책 미적용으로 인터넷에서 내부 API 직접 접근 가능',
     ARRAY[]::TEXT[], ARRAY['dmz', 'ops']);

-- invariant_impact ↔ evidence
INSERT INTO invariant_impact_evidence (impact_id, evidence_id)
    SELECT id, 'evd-s1-account-state-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-01-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_evidence (impact_id, evidence_id)
    SELECT id, 'evd-s1-api-authz-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-05-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_evidence (impact_id, evidence_id)
    SELECT id, 'evd-s1-api-authz-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-arg-01-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_evidence (impact_id, evidence_id)
    SELECT id, 'evd-s1-data-access-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-arg-01-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_evidence (impact_id, evidence_id)
    SELECT id, 'evd-s1-key-state-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-04-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_evidence (impact_id, evidence_id)
    SELECT id, 'evd-s1-token-policy-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-06-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_evidence (impact_id, evidence_id)
    SELECT id, 'evd-s1-gateway-access-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-08-001'
ON CONFLICT DO NOTHING;

-- invariant_impact ↔ registry assets
INSERT INTO invariant_impact_registry_assets (impact_id, asset_id)
    SELECT id, 'APP-OPS-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-01-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_registry_assets (impact_id, asset_id)
    SELECT id, 'APP-OPS-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-05-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_registry_assets (impact_id, asset_id)
    SELECT id, 'APP-DMZ-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-05-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_registry_assets (impact_id, asset_id)
    SELECT id, 'APP-DATA-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-arg-01-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_registry_assets (impact_id, asset_id)
    SELECT id, 'APP-OPS-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-04-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_registry_assets (impact_id, asset_id)
    SELECT id, 'APP-OPS-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-06-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_registry_assets (impact_id, asset_id)
    SELECT id, 'APP-DMZ-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-08-001'
ON CONFLICT DO NOTHING;

-- invariant_impact ↔ services
INSERT INTO invariant_impact_services (impact_id, service_id)
    SELECT id, 'SVC-AUTH-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-01-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_services (impact_id, service_id)
    SELECT id, 'SVC-AUTH-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-05-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_services (impact_id, service_id)
    SELECT id, 'SVC-GW-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-05-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_services (impact_id, service_id)
    SELECT id, 'SVC-DB-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-arg-01-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_services (impact_id, service_id)
    SELECT id, 'SVC-AUTH-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-04-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_services (impact_id, service_id)
    SELECT id, 'SVC-AUTH-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-06-001'
ON CONFLICT DO NOTHING;

INSERT INTO invariant_impact_services (impact_id, service_id)
    SELECT id, 'SVC-GW-001' FROM invariant_impact WHERE result_id = 'ai1-s1-inv-std-08-001'
ON CONFLICT DO NOTHING;
