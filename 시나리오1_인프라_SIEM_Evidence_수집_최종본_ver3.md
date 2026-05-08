# 시나리오1 우선 인프라-SIEM-Evidence 수집 최종본 ver3

## 1. 기본 방향

본 수집 구조는 시나리오 1인 **JWT 서명키 유출 기반 개인정보·기기·영상 메타데이터 유출 시나리오**를 우선 구현하기 위한 것이다.

다만 이후 IoT, OTA, CI/CD, Signing, 공급망 시나리오로 확장할 수 있도록 `event_type` 기반 구조로 설계한다.

```text
각 인프라
→ JSON Lines 로그 또는 State Collector 출력
→ Wazuh Agent
→ argos-security SIEM/Wazuh
→ Evidence Normalizer
→ argos-asset-evidence-v1
→ AI 1 불변식 판단
→ AI 2 공격/진단 체인 생성
```

ver3에서는 ver2의 구조를 유지하면서, AI 1이 불변식 위반을 더 명확히 판단할 수 있도록 **event_type별 observed 필드**를 보강한다.

핵심 원칙은 다음과 같다.

```text
공통 필드는 늘리지 않는다.
추가 필드는 event_type별 observed 안에만 둔다.
의미 없는 필드는 null로 채우지 않고 생략한다.
실제 관찰값과 SIEM 파생 집계값을 구분한다.
민감 원문은 AI payload에 포함하지 않는다.
```

## 2. 용어 정의

| 용어 | 설명 |
|---|---|
| `SIEM` | 각 인프라에서 발생한 로그와 이벤트를 중앙에서 수집·저장·검색하는 시스템. 현재는 `argos-security`의 Wazuh/OpenSearch를 의미 |
| `Wazuh Agent` | 각 VM에 설치되어 로그 파일, syslog, command output 등을 Wazuh Manager로 전송하는 에이전트 |
| `Wazuh Manager` | `argos-security`에 위치한 중앙 수집 서버 |
| `Evidence Normalizer` | SIEM에 수집된 이벤트를 AI 1 입력 형식인 `argos-asset-evidence-v1`로 변환하는 컴포넌트 |
| `AI 1` | Evidence를 기반으로 불변식의 `applied` 또는 `violated`를 판단하는 검증 AI |
| `argos-siem-event-v1` | 각 인프라가 SIEM으로 보내는 수집 이벤트 표준 |
| `argos-asset-evidence-v1` | AI 1이 입력으로 받는 최종 Evidence 표준 |
| `attack_execution` | 실제 공격 요청·인증·인가·데이터 조회 과정에서 발생한 Evidence |
| `environment_state` | 계정, 키, 정책, 로그 보존, 네트워크 설정 등 현재 상태를 나타내는 Evidence |
| `State Collector` | 설정 파일, 정책 테이블, 계정 상태, 키 상태 등을 읽어 SIEM이 수집 가능한 JSON 로그로 출력하는 수집기 |
| `P0` | 시나리오 1 공격 실행을 판단하기 위한 최우선 필수 로그 |
| `P1` | 시나리오 1의 원인과 통제 실패를 판단하기 위한 필수 상태 Evidence |
| `P2` | 향후 확장 시나리오에서 필요한 로그 |
| `필드 소유권` | 특정 필드가 어느 `event_type`에서 생성·관리되어야 하는지에 대한 기준 |
| `실제 관찰값` | API, Gateway, DB 등에서 실제 요청 단위로 발생한 값 |
| `파생 집계값` | SIEM, Detector, Normalizer가 여러 이벤트를 묶어 계산한 값 |

## 3. 우선순위 정의

이번 문서의 우선순위는 구현 난이도가 아니라 **시나리오 1 불변식 판단에 필요한 중요도** 기준이다.

| 우선순위 | 의미 | 현재 구현 여부 |
|---|---|---|
| P0 | 실제 공격 실행 Evidence. 위조 JWT 접근, 내부 API 접근, IDOR, 데이터 반환 등 | 시나리오 1 필수 |
| P1 | 환경 상태 Evidence. 퇴직자, JWT 키, 정책, 로그보존, 네트워크 상태 등 | 시나리오 1 필수 |
| P2 | IoT, OTA, CI/CD, 펌웨어 서명 등 확장 시나리오 Evidence | 추후 확장 |

따라서 시나리오 1을 사례와 비슷하게 구현하려면 **P0 + P1까지 구현해야 한다.**

## 4. `request_id`와 `trace_id`

| 식별자 | 의미 | 사용 목적 |
|---|---|---|
| `request_id` | 단일 HTTP/API 요청 하나의 ID | Gateway/Auth/API/Data 로그를 한 요청 단위로 연결 |
| `trace_id` | 여러 요청 또는 상태 점검 묶음 ID | AI 1이 공격 흐름 전체 또는 상태 점검 흐름을 판단 |

예시:

```text
trace_id = trc-attack-001

request_id = req-001  /internal/api/user-detail?userId=10000001
request_id = req-002  /internal/api/user-detail?userId=10000002
request_id = req-003  /internal/api/device-detail?deviceId=20000001
```

상태 점검 Evidence는 실제 API 요청이 아닐 수 있으므로 아래처럼 사용할 수 있다.

```text
trace_id = state-scan-20260505-001
request_id = state-scan-20260505-001
```

## 5. 공격 실행 Evidence와 환경 상태 Evidence

| 구분 | event_category | 설명 |
|---|---|---|
| 공격 실행 Evidence | `attack_execution` | 실제 공격 요청, 인증, 인가, 데이터 조회, 대량 조회 과정에서 발생한 로그 |
| 환경 상태 Evidence | `environment_state` | 정책, 설정, 계정, 키, 로그 보존, 네트워크 상태를 나타내는 로그 |

AI 1 입력 Evidence로 변환할 때는 다음처럼 넣는다.

```json
{
  "control": {
    "evidence_category": "environment_state"
  }
}
```

## 6. State Collector 필요성

Wazuh는 로그를 수집할 수 있지만, 애플리케이션 내부 설정값이나 DB 정책값을 자동으로 이해해서 Evidence로 만들어주지는 않는다.

따라서 다음과 같은 상태값은 State Collector가 별도로 수집해야 한다.

```text
validate_jti_registry
validate_revocation
validate_kid_active
validate_issuer
validate_audience
validate_iat
owner_check_enabled
tenant_check_enabled
authz_service_enabled
credential_status
key_status
storage_location_type
stored_in_approved_secret_manager
retired_user_had_access
last_rotated_at
key_rotation_completed
retention_lock_enabled
tamper_detection_enabled
external_access_to_internal_api_allowed
```

State Collector가 필요한 이유는 다음과 같다.

| 이유 | 설명 |
|---|---|
| 설정값은 access log에 남지 않음 | 예: `validate_jti_registry=false`는 요청 로그가 아니라 정책 상태 |
| 시나리오 원인 판단에 필요 | 퇴직자 키 접근, 키 회전 실패, 검증 정책 미흡 등을 증명 |
| AI 1의 `clear_violation` 근거가 됨 | 단순 추정이 아니라 실제 상태값 기반 판단 가능 |
| 향후 확장성 확보 | OTA, Signing, MQTT 정책 상태도 같은 방식으로 확장 가능 |

## 7. State Collector 구성 방식

권장 구조는 다음과 같다.

```text
정책 테이블 / 설정 파일 / 계정 테이블 / 키 상태 테이블
→ State Collector가 주기적으로 조회
→ argos-siem-event-v1 JSON 생성
→ /var/log/argos/state/*.jsonl 기록
→ Wazuh Agent 수집
→ argos-security Evidence Normalizer
→ argos-asset-evidence-v1 변환
```

예시:

```json
{
  "schema_version": "argos-siem-event-v1",
  "event_id": "evt-token-policy-001",
  "timestamp": "2026-05-05T14:00:00+09:00",
  "trace_id": "state-scan-20260505-001",
  "request_id": "state-scan-20260505-001",
  "event_category": "environment_state",
  "producer": {
    "vm": "argos-ops",
    "component_id": "argos-ops-token-policy-collector",
    "component_type": "state_collector",
    "zone": "ops"
  },
  "event_type": "token_policy_state",
  "observed": {
    "auth_method": "JWT Bearer",
    "validate_signature": true,
    "validate_issuer": false,
    "validate_audience": false,
    "validate_jti_registry": false,
    "validate_revocation": false,
    "validate_kid_active": false
  },
  "raw_ref": {
    "source": "auth_policy_table",
    "log_id": "token-policy-001"
  }
}
```

## 8. 공통 SIEM 이벤트 포맷

공통 SIEM 이벤트 포맷은 ver2와 동일하게 유지한다.

```json
{
  "schema_version": "argos-siem-event-v1",
  "event_id": "evt-001",
  "timestamp": "2026-05-05T14:00:00+09:00",
  "trace_id": "trc-attack-001",
  "request_id": "req-001",
  "event_category": "attack_execution",
  "producer": {
    "vm": "argos-ops",
    "component_id": "argos-ops-api",
    "component_type": "api",
    "zone": "ops"
  },
  "event_type": "api_authorization_event",
  "observed": {},
  "raw_ref": {
    "source": "api_audit_log",
    "log_id": "api-001"
  }
}
```

## 9. 공통 필드 설명

| 필드 | 설명 |
|---|---|
| `schema_version` | SIEM 수집 이벤트 버전. `argos-siem-event-v1` |
| `event_id` | 개별 이벤트 ID |
| `timestamp` | 이벤트 발생 시각 |
| `trace_id` | 공격 흐름 또는 상태 점검 흐름 ID |
| `request_id` | 단일 요청 또는 상태 점검 ID |
| `event_category` | `attack_execution` 또는 `environment_state` |
| `producer.vm` | 이벤트 생성 VM |
| `producer.component_id` | 이벤트 생성 컴포넌트 |
| `producer.component_type` | 컴포넌트 유형 |
| `producer.zone` | 인프라 구역 |
| `event_type` | 이벤트 유형 |
| `observed` | 실제 관찰 필드 또는 event_type별 파생 필드 |
| `raw_ref` | 원본 로그 참조 |

## 9.1 event_type별 필드 소유권

| event_type | 담당 의미 | 주요 필드 |
|---|---|---|
| `account_state_event` | 퇴직자·계정·credential 상태 | `employment_status`, `account_status`, `credential_status` |
| `privileged_access_state` | 개발자·관리자 권한 상태 | `production_secret_access_allowed`, `production_customer_data_access_allowed` |
| `key_management_state` | JWT 서명키 관리 상태 | `key_id`, `key_type`, `key_status`, `last_rotated_at` |
| `token_policy_state` | JWT 검증 정책 상태 | `validate_jti_registry`, `validate_revocation`, `validate_kid_active` |
| `token_validation_event` | 개별 JWT 검증 결과 | `signature_valid`, `issued_by_auth_server`, `token_jti`, `token_kid` |
| `api_authorization_event` | API 인가 판단 결과 | `owner_check_performed`, `tenant_check_performed`, `authorization_decision` |
| `gateway_access_event` | DMZ/API Gateway 접근 | `source_zone`, `internal_path_requested`, `waf_action` |
| `network_policy_state` | DMZ 네트워크 정책 상태 | `external_access_to_internal_api_allowed`, `default_internal_path_action` |
| `data_access_event` | DB/Object 조회 결과 | `resource_owner_id`, `resource_tenant_id`, `sensitive_field_types` |
| `aggregation_state` | 대량·순차·분산 조회 탐지 결과 | `request_count`, `distinct_owner_count`, `risk_score` |
| `log_trace_state` | 계층별 로그 연결 상태 | `gateway_log_present`, `api_log_present`, `data_log_present` |
| `log_retention_state` | 로그 보존·변조 방지 상태 | `retention_lock_enabled`, `log_deleted_after_incident` |

## 9.2 필드 경계 및 혼동 방지 기준

### `token_kid`와 `key_id`

| 필드 | 의미 |
|---|---|
| `token_kid` | JWT header에 들어온 key id |
| `key_id` | 실제 키 관리 시스템 또는 정책 테이블에 등록된 키 ID |

`token_kid`는 요청자가 들고 온 토큰의 주장값이고, `key_id`는 서버가 관리하는 실제 키 자산이다.

AI 1은 두 값을 함께 보고 다음을 판단한다.

```text
token_kid가 참조한 키가 실제 key_management_state에 존재하는가
해당 key_id가 active 상태인가
퇴직자 접근 이후 key_rotation_completed가 true인가
```

### `credential_status`와 `key_status`

| 필드 | 의미 |
|---|---|
| `credential_status` | 계정, 세션, API Key, 서비스 토큰 같은 계정성 credential 상태 |
| `key_status` | JWT 서명키 자체의 상태 |

퇴직자 계정이 비활성화되었는지는 `account_status`와 `credential_status`로 판단한다.  
JWT 서명키가 회전 또는 폐기되었는지는 `key_status`, `last_rotated_at`, `key_rotation_completed`로 판단한다.

### `authorization_decision`, `waf_action`, `alert_created`

| 필드 | 의미 |
|---|---|
| `authorization_decision` | API 또는 Authz Service가 접근을 허용/차단했는지 |
| `waf_action` | DMZ/WAF/Gateway가 요청을 허용/차단/탐지만 했는지 |
| `alert_created` | SIEM/Detector가 이상행위 alert를 만들었는지 |

예시:

```text
waf_action = allow
authorization_decision = allow
alert_created = false
```

이 경우 AI 1은 내부 API 외부 접근, 인가 실패, 탐지 실패를 각각 다른 불변식 위반으로 판단할 수 있다.

### 실제 관찰값과 파생 집계값

| 구분 | 예시 | 생성 주체 |
|---|---|---|
| 실제 관찰값 | `endpoint`, `status_code`, `token_sub`, `resource_owner_id` | API, Gateway, DB |
| 파생 집계값 | `distinct_owner_count`, `sequential_id_pattern`, `risk_score` | SIEM, Detector, Normalizer |

### 원문 값과 참조값

| 금지 | 허용 |
|---|---|
| JWT 원문 | `token_jti`, `token_kid`, `raw_ref.log_id` |
| JWT Secret 원문 | `key_id`, `key_status`, `storage_location_type` |
| 개인정보 원문 | `sensitive_field_types`, `contains_address` |
| 영상 URL 원문 | `contains_video_access_url`, `object_key_hash` |

AI payload에는 원문을 넣지 않는다.

## 10. 인프라별 수집 항목

## 10.1 `argos-mgmt` P1

**기능**  
퇴직자 계정, 개발자 권한, credential 상태를 제공한다.

**event_type**

```text
account_state_event
privileged_access_state
identity_auth_event
```

**필드**

| 필드 | 설명 |
|---|---|
| `account_id` | 계정 ID |
| `employment_status` | 재직/퇴직 상태 |
| `account_status` | 계정 활성/비활성 상태 |
| `credential_status` | credential 활성/폐기 상태 |
| `active_session_count` | 활성 세션 수 |
| `api_key_status` | API Key 상태 |
| `service_token_status` | 서비스 토큰 상태 |
| `role` | 계정 역할 |
| `groups` | AD/LDAP 그룹 |
| `had_jwt_key_access` | JWT 서명키 접근 이력 |
| `production_secret_access_allowed` | 운영 Secret 접근 가능 여부 |
| `production_customer_data_access_allowed` | 운영 고객정보 접근 가능 여부 |

**예시**

```json
{
  "schema_version": "argos-siem-event-v1",
  "event_id": "evt-account-001",
  "timestamp": "2026-05-05T14:00:00+09:00",
  "trace_id": "state-scan-20260505-001",
  "request_id": "state-scan-20260505-001",
  "event_category": "environment_state",
  "producer": {
    "vm": "argos-mgmt",
    "component_id": "argos-account-state-collector",
    "component_type": "state_collector",
    "zone": "mgmt"
  },
  "event_type": "account_state_event",
  "observed": {
    "account_id": "exuser1",
    "employment_status": "retired",
    "account_status": "disabled",
    "credential_status": "active",
    "active_session_count": 0,
    "api_key_status": "revoked",
    "service_token_status": "active",
    "role": "former_auth_developer",
    "groups": ["Terminated"],
    "had_jwt_key_access": true
  }
}
```

## 10.2 `argos-ops` P0 + P1

**기능**  
JWT 검증, API 인가, JWT 키 상태, Authz 정책 상태를 제공한다.

**event_type**

```text
token_validation_event
api_authorization_event
token_policy_state
key_management_state
authz_policy_state
privileged_access_event
```

**필드**

| 필드 | 설명 |
|---|---|
| `actor_id` | 요청 주체 ID |
| `actor_role` | 요청 주체 역할 |
| `source_ip` | 요청 출발 IP |
| `token_present` | 토큰 존재 여부 |
| `token_sub` | JWT subject |
| `token_tenant` | JWT tenant |
| `token_role` | JWT role claim |
| `token_scope` | JWT scope claim |
| `token_jti` | JWT ID |
| `token_kid` | JWT header에 포함된 key id |
| `iss` | JWT issuer |
| `aud` | JWT audience |
| `iat` | JWT 발급 시각 |
| `exp` | JWT 만료 시각 |
| `signature_valid` | 서명 검증 결과 |
| `issued_by_auth_server` | 정상 발급 이력 여부 |
| `kid_active` | `token_kid`가 현재 활성 키인지 여부 |
| `revoked` | 폐기 토큰 여부 |
| `expired` | 만료 토큰 여부 |
| `validate_signature` | JWT 서명 검증 정책 |
| `validate_issuer` | issuer 검증 정책 |
| `validate_audience` | audience 검증 정책 |
| `validate_expiration` | 만료 검증 정책 |
| `validate_iat` | 발급 시각 검증 정책 |
| `validate_kid_active` | kid 활성 여부 검증 정책 |
| `validate_jti_registry` | jti 발급 저장소 검증 정책 |
| `validate_revocation` | 폐기 토큰 검증 정책 |
| `token_registry_enabled` | 정상 발급 토큰 저장소 운영 여부 |
| `revocation_list_enabled` | 폐기 목록 운영 여부 |
| `key_id` | 실제 키 관리 시스템 또는 정책 테이블의 키 ID |
| `key_type` | 키 유형 |
| `key_status` | 키 상태 |
| `storage_location_type` | 키 저장 위치 |
| `stored_in_approved_secret_manager` | 승인된 키 관리 체계 저장 여부 |
| `retired_user_had_access` | 퇴직자가 키에 접근한 이력 여부 |
| `last_rotated_at` | 마지막 키 회전 시각 |
| `previous_key_status` | 이전 키 상태 |
| `key_rotation_required` | 키 회전 필요 여부 |
| `key_rotation_completed` | 키 회전 완료 여부 |
| `endpoint` | 호출 API |
| `method` | HTTP method |
| `target_identifier` | 입력된 `userId`, `deviceId`, `videoId` |
| `resource_type` | 접근 대상 자산 유형 |
| `resource_id` | 접근 대상 자산 ID |
| `resource_owner_id` | 실제 자산 owner |
| `resource_tenant_id` | 실제 자산 tenant |
| `owner_check_performed` | owner 검증 수행 여부 |
| `tenant_check_performed` | tenant 검증 수행 여부 |
| `authz_service_used` | 중앙 권한 검증 사용 여부 |
| `authz_service_enabled` | 중앙 권한 서비스 또는 권한 테이블 운영 여부 |
| `authorization_decision` | 접근 허용/차단 결과 |
| `required_role` | API 접근 필요 역할 |
| `required_scope` | API 접근 필요 scope |
| `status_code` | 응답 코드 |
| `page_size` | 요청 page size |
| `bulk_export` | 대량 export 요청 여부 |
| `response_fields` | 응답 필드 목록. 값 원문은 금지 |
| `contains_address` | 주소 포함 여부 |
| `contains_install_location` | 설치 위치 포함 여부 |
| `contains_door_access_info` | 공동출입정보 포함 여부 |
| `contains_video_access_url` | 영상 접근 URL 포함 여부 |
| `contains_thumbnail_url` | 썸네일 URL 포함 여부 |
| `contains_object_key` | object key 포함 여부 |
| `contains_sensor_log` | 센서 로그 포함 여부 |
| `ticket_id` | 고객지원/운영 접근 티켓 ID |
| `access_reason` | 민감정보 접근 사유 |
| `audit_log_created` | 감사 로그 생성 여부 |

**공격 실행 예시**

```json
{
  "schema_version": "argos-siem-event-v1",
  "event_id": "evt-api-001",
  "timestamp": "2026-05-05T14:01:00+09:00",
  "trace_id": "trc-attack-001",
  "request_id": "req-001",
  "event_category": "attack_execution",
  "producer": {
    "vm": "argos-ops",
    "component_id": "argos-ops-api",
    "component_type": "api",
    "zone": "ops"
  },
  "event_type": "api_authorization_event",
  "observed": {
    "actor_id": "customer_a",
    "actor_role": "user",
    "source_ip": "10.10.1.2",
    "token_present": true,
    "token_sub": "customer_a",
    "token_tenant": "tenant-a",
    "token_role": "user",
    "token_scope": "profile:read device:read video:read",
    "token_jti": "jti-forged-001",
    "token_kid": "kid-old-001",
    "signature_valid": true,
    "issued_by_auth_server": false,
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
    "required_role": "user",
    "required_scope": "profile:read",
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
  }
}
```

**토큰 정책 상태 예시**

```json
{
  "schema_version": "argos-siem-event-v1",
  "event_id": "evt-token-policy-001",
  "timestamp": "2026-05-05T14:00:00+09:00",
  "trace_id": "state-scan-20260505-001",
  "request_id": "state-scan-20260505-001",
  "event_category": "environment_state",
  "producer": {
    "vm": "argos-ops",
    "component_id": "argos-token-policy-collector",
    "component_type": "state_collector",
    "zone": "ops"
  },
  "event_type": "token_policy_state",
  "observed": {
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
  }
}
```

**키 상태 예시**

```json
{
  "schema_version": "argos-siem-event-v1",
  "event_id": "evt-key-state-001",
  "timestamp": "2026-05-05T14:00:00+09:00",
  "trace_id": "state-scan-20260505-001",
  "request_id": "state-scan-20260505-001",
  "event_category": "environment_state",
  "producer": {
    "vm": "argos-ops",
    "component_id": "argos-key-state-collector",
    "component_type": "state_collector",
    "zone": "ops"
  },
  "event_type": "key_management_state",
  "observed": {
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
  }
}
```

## 10.3 `argos-dmz` P0 + P1

**기능**  
외부에서 내부 API 접근이 가능한지 제공한다.

**event_type**

```text
gateway_access_event
network_policy_state
```

**필드**

| 필드 | 설명 |
|---|---|
| `source_ip` | 요청 IP |
| `source_zone` | 요청 출발 구역 |
| `destination_zone` | 요청 도착 구역 |
| `method` | HTTP method |
| `uri` | 원본 URI |
| `normalized_endpoint` | 정규화된 endpoint |
| `endpoint_group` | `/api`, `/internal`, `/admin`, `/ota` 등 경로 그룹 |
| `internal_path_requested` | `/internal/*` 요청 여부 |
| `forwarded_to` | 전달된 upstream 대상 |
| `upstream` | 요청이 전달된 내부 upstream |
| `status_code` | Gateway 응답 코드 |
| `allowed_path` | 승인된 접근 경로 여부 |
| `waf_action` | allow/block/detect |
| `rate_limited` | rate limit 작동 여부 |
| `vpn_user` | VPN 사용자 |
| `external_access_to_internal_api_allowed` | 내부 API 외부 노출 정책 |
| `default_internal_path_action` | `/internal/*` 기본 처리 |
| `allowed_source_zones` | 내부 API 접근 허용 source zone 목록 |
| `rate_limit_policy_enabled` | rate limit 정책 활성화 여부 |

**예시**

```json
{
  "schema_version": "argos-siem-event-v1",
  "event_id": "evt-dmz-001",
  "timestamp": "2026-05-05T14:00:00+09:00",
  "trace_id": "trc-attack-001",
  "request_id": "req-001",
  "event_category": "attack_execution",
  "producer": {
    "vm": "argos-dmz",
    "component_id": "argos-dmz-nginx",
    "component_type": "gateway",
    "zone": "dmz"
  },
  "event_type": "gateway_access_event",
  "observed": {
    "source_ip": "203.0.113.10",
    "source_zone": "internet",
    "destination_zone": "ops",
    "method": "GET",
    "uri": "/internal/api/user-detail?userId=10000002",
    "normalized_endpoint": "/internal/api/user-detail",
    "endpoint_group": "/internal",
    "status_code": 200,
    "upstream": "10.10.3.2:8080",
    "internal_path_requested": true,
    "forwarded_to": "argos-ops",
    "allowed_path": false,
    "waf_action": "allow",
    "rate_limited": false,
    "vpn_user": null
  }
}
```

## 10.4 `argos-data` P0 + P1

**기능**  
실제 데이터 반환, DB/Object 접근, 로그 보존 상태를 제공한다.

**event_type**

```text
data_access_event
object_storage_access_event
log_retention_state
```

**필드**

| 필드 | 설명 |
|---|---|
| `db_user` | DB 접속 계정 |
| `query_type` | SELECT/INSERT/UPDATE/DELETE |
| `table_name` | 접근 테이블 |
| `query_result` | success/fail |
| `resource_type` | 조회 자산 유형 |
| `resource_id` | 조회 자산 ID |
| `resource_owner_id` | 조회 자산 owner |
| `resource_tenant_id` | 조회 자산 tenant |
| `record_count` | 조회 건수 |
| `sensitive_field_types` | 민감 필드 유형 |
| `data_returned` | 데이터 반환 여부 |
| `pii_value_included` | 개인정보 원문 포함 여부. AI payload에서는 false여야 함 |
| `minio_bucket` | 접근 bucket |
| `minio_object_key_hash` | object key hash/ref |
| `object_owner_id` | object 소유자 |
| `object_tenant_id` | object tenant |
| `object_event` | GetObject/ListObject/DeleteObject 등 |
| `content_length` | 반환 크기 |
| `log_source` | 로그 출처 |
| `retention_days` | 로그 보존 기간 |
| `retention_lock_enabled` | 로그 보존 잠금 적용 여부 |
| `tamper_detection_enabled` | 로그 변조 탐지 적용 여부 |
| `incident_status` | 사고 상태 |
| `incident_detected_at` | 사고 인지 시각 |
| `retention_policy_locked_at` | 로그 보존 정책 잠금 시각 |
| `log_deleted_after_incident` | 사고 인지 이후 로그 삭제 여부 |

**예시**

```json
{
  "schema_version": "argos-siem-event-v1",
  "event_id": "evt-data-001",
  "timestamp": "2026-05-05T14:02:00+09:00",
  "trace_id": "trc-attack-001",
  "request_id": "req-001",
  "event_category": "attack_execution",
  "producer": {
    "vm": "argos-data",
    "component_id": "argos-postgresql",
    "component_type": "database",
    "zone": "data"
  },
  "event_type": "data_access_event",
  "observed": {
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
  }
}
```

**로그 보존 상태 예시**

```json
{
  "schema_version": "argos-siem-event-v1",
  "event_id": "evt-log-retention-001",
  "timestamp": "2026-05-05T14:30:00+09:00",
  "trace_id": "state-scan-20260505-001",
  "request_id": "state-scan-20260505-001",
  "event_category": "environment_state",
  "producer": {
    "vm": "argos-data",
    "component_id": "argos-log-retention-collector",
    "component_type": "state_collector",
    "zone": "data"
  },
  "event_type": "log_retention_state",
  "observed": {
    "log_source": "db",
    "retention_days": 7,
    "retention_lock_enabled": false,
    "tamper_detection_enabled": false,
    "incident_status": "suspected",
    "incident_detected_at": "2026-05-05T14:20:00+09:00",
    "retention_policy_locked_at": null,
    "log_deleted_after_incident": true
  }
}
```

## 10.5 `argos-security` P0 + P1

**기능**  
SIEM, Wazuh, Normalizer, Detector, AI 1/AI 2가 위치한다.

**event_type**

```text
aggregation_state
log_trace_state
wazuh_alert_event
central_job_metadata
```

**필드**

| 필드 | 설명 |
|---|---|
| `agent_id` | Wazuh Agent ID |
| `rule_id` | Wazuh rule ID |
| `raw_log_id` | 원본 로그 ID |
| `invariant_id` | 연결 가능한 불변식 ID |
| `actor_id` | 집계 대상 actor |
| `source_ip` | 집계 대상 IP |
| `token_jti` | 집계 대상 token |
| `window_seconds` | 집계 시간 범위 |
| `request_count` | 시간 범위 내 요청 수 |
| `distinct_source_ip_count` | 동일 actor/token 기준 서로 다른 source IP 수 |
| `distinct_owner_count` | 서로 다른 owner 조회 수 |
| `distinct_tenant_count` | 서로 다른 tenant 조회 수 |
| `distinct_device_count` | 서로 다른 device 조회 수 |
| `distinct_video_count` | 서로 다른 video 조회 수 |
| `sequential_id_pattern` | 순차 조회 여부 |
| `threshold_value` | 탐지 기준 임계치 |
| `risk_score` | 위험 점수 |
| `alert_created` | alert 생성 여부 |
| `log_trace_gap` | trace 단절 여부 |
| `evidence_missing` | 필요한 Evidence 누락 여부 |
| `gateway_log_present` | Gateway 로그 존재 여부 |
| `auth_log_present` | Auth 로그 존재 여부 |
| `api_log_present` | API 로그 존재 여부 |
| `data_log_present` | Data 로그 존재 여부 |

**집계 예시**

```json
{
  "schema_version": "argos-siem-event-v1",
  "event_id": "evt-aggregation-001",
  "timestamp": "2026-05-05T14:10:00+09:00",
  "trace_id": "trc-attack-001",
  "request_id": "aggregation-001",
  "event_category": "environment_state",
  "producer": {
    "vm": "argos-security",
    "component_id": "argos-siem-detector",
    "component_type": "detector",
    "zone": "security"
  },
  "event_type": "aggregation_state",
  "observed": {
    "actor_id": "customer_a",
    "token_jti": "jti-forged-001",
    "source_ip": "203.0.113.10",
    "window_seconds": 300,
    "request_count": 150,
    "distinct_source_ip_count": 12,
    "distinct_owner_count": 80,
    "distinct_tenant_count": 5,
    "distinct_device_count": 42,
    "distinct_video_count": 90,
    "sequential_id_pattern": true,
    "threshold_value": 20,
    "risk_score": 92,
    "alert_created": false
  }
}
```

**로그 trace 예시**

```json
{
  "schema_version": "argos-siem-event-v1",
  "event_id": "evt-trace-001",
  "timestamp": "2026-05-05T14:10:00+09:00",
  "trace_id": "trc-attack-001",
  "request_id": "trace-check-001",
  "event_category": "environment_state",
  "producer": {
    "vm": "argos-security",
    "component_id": "argos-evidence-normalizer",
    "component_type": "normalizer",
    "zone": "security"
  },
  "event_type": "log_trace_state",
  "observed": {
    "agent_id": "argos-security-normalizer",
    "raw_log_id": "trace-check-001",
    "invariant_id": "INV-STD-10",
    "gateway_log_present": true,
    "auth_log_present": true,
    "api_log_present": true,
    "data_log_present": false,
    "log_trace_gap": true,
    "evidence_missing": true,
    "missing_layers": ["data"]
  }
}
```

## 11. 불변식별 필요한 Evidence 매핑표

ver3에서는 최신 `최종_불변식_목록_쿠팡사례_아르고스.md` 기준으로 ID를 맞춘다.

| 불변식 | AI 1이 확인해야 할 핵심 Evidence |
|---|---|
| `INV-STD-01` | `account_id`, `employment_status`, `account_status`, `credential_status`, `active_session_count`, `api_key_status`, `service_token_status` |
| `INV-STD-02` | `account_id`, `role`, `production_secret_access_allowed`, `production_customer_data_access_allowed` |
| `INV-STD-03` | `key_id`, `key_type`, `storage_location_type`, `stored_in_approved_secret_manager` |
| `INV-STD-04` | `key_id`, `retired_user_had_access`, `key_status`, `last_rotated_at`, `previous_key_status`, `key_rotation_completed` |
| `INV-STD-05` | `signature_valid`, `issued_by_auth_server`, `token_jti`, `token_kid`, `kid_active`, `expired`, `revoked`, `authorization_decision`, `endpoint` |
| `INV-STD-06` | `validate_signature`, `validate_issuer`, `validate_audience`, `validate_iat`, `validate_jti_registry`, `validate_revocation`, `token_registry_enabled`, `revocation_list_enabled` |
| `INV-STD-07` | `token_sub`, `resource_owner_id`, `owner_check_performed`, `authorization_decision`, `status_code` |
| `INV-STD-08` | `normalized_endpoint`, `endpoint_group`, `source_zone`, `destination_zone`, `internal_path_requested`, `allowed_path`, `waf_action`, `status_code` |
| `INV-STD-09` | `actor_id`, `token_jti`, `source_ip`, `request_count`, `distinct_source_ip_count`, `page_size`, `bulk_export`, `sequential_id_pattern`, `threshold_value`, `alert_created` |
| `INV-STD-10` | `request_id`, `trace_id`, `gateway_log_present`, `auth_log_present`, `api_log_present`, `data_log_present`, `log_trace_gap` |
| `INV-STD-11` | `log_source`, `retention_days`, `retention_lock_enabled`, `tamper_detection_enabled`, `incident_status`, `log_deleted_after_incident` |
| `INV-STD-12` | `actor_role`, `resource_type`, `ticket_id`, `access_reason`, `audit_log_created` |
| `INV-STD-13` | `role`, `production_secret_access_allowed`, `production_customer_data_access_allowed` |
| `INV-STD-14` | `source_zone`, `destination_zone`, `allowed_path`, `vpn_user`, `key_id`, `key_status`, `storage_location_type` |
| `INV-ARG-01` | `token_tenant`, `resource_tenant_id`, `tenant_check_performed`, `authorization_decision` |
| `INV-ARG-02` | `token_sub`, `resource_owner_id`, `resource_tenant_id`, `authorization_decision` |
| `INV-ARG-03` | `target_identifier`, `token_sub`, `resource_owner_id`, `resource_tenant_id`, `owner_check_performed`, `status_code` |
| `INV-ARG-04` | `contains_address`, `contains_install_location`, `contains_door_access_info`, `owner_check_performed`, `tenant_check_performed` |
| `INV-ARG-05` | `contains_video_access_url`, `contains_thumbnail_url`, `contains_object_key`, `contains_sensor_log`, `owner_check_performed`, `tenant_check_performed` |
| `INV-ARG-06` | `distinct_owner_count`, `distinct_tenant_count`, `distinct_device_count`, `distinct_video_count`, `sequential_id_pattern`, `alert_created` |
| `INV-ARG-07` | `authz_service_used`, `authz_service_enabled`, `authorization_decision` |
| `INV-ARG-08` | `endpoint`, `token_role`, `token_scope`, `required_role`, `required_scope`, `authorization_decision`, `status_code` |

## 12. P2 확장 가능 항목

아래 항목은 현재 시나리오 1의 필수 구현 범위는 아니지만, 최종 구조에는 확장 가능한 부분으로 포함한다.

### 12.1 `argos-iot`

**확장 event_type**

```text
mqtt_connection_event
device_auth_event
```

**확장 필드**

```text
device_id
mqtt_client_id
topic
anonymous_connection
auth_result
device_owner_id
device_tenant_id
certificate_valid
```

**향후 시나리오**

```text
IoT 인증 우회
가짜 기기 접속
MQTT topic 무단 구독
```

### 12.2 `argos-deploy`

**확장 event_type**

```text
jenkins_build_event
deployment_event
ota_event
repo_access_event
```

**확장 필드**

```text
repository
branch
commit_id
committer
build_id
build_status
artifact_hash
firmware_version
deployment_group
target_device_count
internal_token_validation_result
```

**향후 시나리오**

```text
CI/CD 장악
OTA 배포 변조
Git Secret 유출
```

### 12.3 `argos-signing`

**확장 event_type**

```text
firmware_signing_event
key_file_integrity_event
```

**확장 필드**

```text
caller_ip
caller_component
allowlist_passed
build_id
firmware_hash
key_id
key_location_type
algorithm
signing_result
denied_reason
key_material_exposed
```

**향후 시나리오**

```text
펌웨어 서명키 유출
악성 펌웨어 서명
Signing Server 접근통제 실패
```

## 13. Wazuh 수집 경로와 Normalizer

### 13.1 공격 실행 로그

```text
서비스가 JSON Lines 로그 생성
→ /var/log/argos/*.jsonl
→ Wazuh Agent localfile 수집
→ argos-security Wazuh Manager
→ OpenSearch
→ Evidence Normalizer
```

### 13.2 상태 Evidence

```text
State Collector가 JSON Lines 로그 생성
→ /var/log/argos/state/*.jsonl
→ Wazuh Agent localfile 수집
→ argos-security Wazuh Manager
→ OpenSearch
→ Evidence Normalizer
```

### 13.3 Wazuh 설정 예시

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/argos/api_authorization.jsonl</location>
</localfile>
```

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/argos/state/token_policy_state.jsonl</location>
</localfile>
```

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/argos/state/key_management_state.jsonl</location>
</localfile>
```

### 13.4 Normalizer 역할

Evidence Normalizer는 다음을 수행한다.

```text
1. Wazuh/OpenSearch에서 argos-siem-event-v1 이벤트를 조회한다.
2. event_type에 따라 asset, actor, token, access, control 필드로 매핑한다.
3. 민감 원문은 제거하고 raw_ref만 유지한다.
4. trace_id/request_id 기준으로 Evidence를 묶는다.
5. 실제 관찰값과 파생 집계값을 구분한다.
6. argos-asset-evidence-v1로 변환한다.
7. AI 1에 단건 또는 batch로 전달한다.
```

AI 1 전달 예시:

```text
POST /ai1/v1/asset-evidence
POST /ai1/v1/asset-evidence/batch
```

## 14. 최종 결론

시나리오 1을 사례와 비슷하게 구현하려면 P0만으로는 부족하다.  
퇴직자 내부자, JWT 서명키 접근, 키 회전 실패, 정책 미흡까지 설명해야 하므로 **P0 + P1이 현재 시나리오 1의 필수 구현 범위**다.

```text
P0:
공격 실행 Evidence

P1:
퇴직자·JWT 키·정책·로그보존 상태 Evidence

P2:
IoT, OTA, CI/CD, 펌웨어 서명 등 확장 Evidence
```

ver3는 ver2의 항목을 유지하면서 다음을 보강한다.

```text
1. key_management_state 필드 보강
2. token_policy_state 필드 보강
3. token_validation_event 필드 보강
4. api_authorization_event 필드 보강
5. aggregation_state 필드 보강
6. log_retention_state 필드 보강
7. 필드 경계 및 혼동 방지 기준 추가
8. 최신 불변식 목록 기준 Evidence 매핑표 보강
```

따라서 ver3는 ver2를 대체해서 축약한 문서가 아니라, **ver2의 전체 흐름과 항목을 유지한 상태에서 AI 1 판단 정확도를 높이기 위해 필드와 설명을 보강한 업데이트본**이다.
