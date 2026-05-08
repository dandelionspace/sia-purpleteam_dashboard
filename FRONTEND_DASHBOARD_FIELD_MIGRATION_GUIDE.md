# Frontend Dashboard Field Migration Guide

기준일: 2026-05-06  
대상: Argos 보안 관리자 대시보드 프론트 작업자 및 프론트 에이전트

이 문서는 현재 프론트 저장소 `sia-purpleteam_dashboard`의 데이터 필드와, Scenario 1 기준 Argos 보안 시스템의 최종 데이터 계약을 비교해 대시보드 필드를 통일하기 위한 단일 handoff 문서다. 프론트는 실제 기업 환경에 배포된 보안 관리자 대시보드를 기준으로 타입, 화면, 더미 데이터를 설계한다.

주의: 프론트 더미 데이터와 API 계약은 개발자 개인 환경, 내부 개발 경로, 임시 실행 산출물명을 노출하지 않는다. 예시 payload는 실제 운영 환경에 그대로 들어가도 어색하지 않은 중립적인 ID, 서비스명, 설명만 사용한다. 현재 수집되지 않은 필드는 빈 배열, `null`, `unknown`, `not_collected_yet` 상태로 표시한다.

핵심 결론은 다음이다.

```text
프론트 화면 구조:
  기존 scan/detail 중심 구조 유지

필드 기준:
  시나리오1_인프라_SIEM_Evidence_수집_최종본_ver3.md + Argos 운영 데이터 계약 기준

운영 전환:
  dashboard_adapter가 중앙 보안 시스템 산출물을 GET /api/scans,
  GET /api/scans/{scan_id}/details 형태로 변환
```

## 1. 목적

프론트와 AI/보안 시스템이 병렬로 개발되면서 같은 의미의 필드가 서로 다른 이름으로 존재한다. 이 문서는 프론트가 어떤 필드를 유지하고, 어떤 필드를 제거하며, 어떤 필드를 Argos 배포 기준으로 rename해야 하는지 명확히 정리한다.

프론트 저장소 자체의 디자인, 메뉴, 대시보드 흐름은 유지한다. 단, 데이터 계약은 ver3 Evidence 수집 계약과 Argos 통합 산출물 기준으로 맞춘다.

프론트가 반드시 구분해야 하는 기준은 다음이다.

```text
현재 개발 샘플:
  Scenario 1의 일부 event_type과 핵심 불변식 중심으로 생성된 승인 검증 데이터

완성본 기준:
  22개 전체 불변식, 모든 VM collector, event_type별 observed 필드,
  자산 registry, AI1, AI2, Red Team 검증 결과를 모두 수용하는 데이터 모델
```

대시보드의 기본 관점은 AI 중심이 아니라 **보안 관리자가 직접 탐색하는 자산 중심**이다. AI1/AI2는 사람이 찾아야 할 내용을 미리 정리하고 연결해주는 보조 레이어다.

```text
1차 화면:
  자산, 서버, 서비스, 계정/권한, Evidence, 변경 이력 직접 탐색

2차 화면:
  AI1이 정리한 불변식 위반 후보

3차 화면:
  AI2가 묶은 공격 체인 후보와 Red Team 검증 결과
```

기준 소스:

```text
프론트 저장소:
  https://github.com/dandelionspace/sia-purpleteam_dashboard

운영 API 기준:
  GET /api/scans
  GET /api/scans/{scan_id}/details
  POST /api/ai1/results
  POST /api/ai2/scenarios
  POST /api/scans/{scan_id}/pentest
```

## 2. 현재 프론트 저장소 데이터 구조

현재 프론트 저장소는 `scan`과 `scan_detail` 중심으로 화면을 구성한다. 이 구조는 유지해도 된다.

구조 보존 원칙:

```text
유지:
  Dashboard.jsx의 scan 선택 흐름
  KpiCards
  ScanSection
  ViolationSection
  InvariantSection
  AttackSection
  AssetSection
  PentestSection

수정:
  각 섹션 내부에서 사용하는 필드명과 데이터 매핑

추가:
  AssetSection 안에 서버/서비스/권한/Evidence 탐색 탭
  ViolationSection 안에 evidence_refs와 affected_assets 표시
  AttackSection 안에 AI2 체인 노드별 invariant/evidence 연결 표시
```

기존 컴포넌트를 크게 갈아엎지 말고, 기존 props와 section 구조 위에 필드를 보강한다. 특히 기존 `scan/detail` API 구조는 유지한다.

### 2.1 API endpoint

| Endpoint | 현재 역할 | 유지 여부 |
|---|---|---|
| `GET /api/scans` | 스캔 목록 조회 | 유지 |
| `GET /api/scans/{scan_id}/details` | 스캔 상세 조회 | 유지 |
| `POST /api/scans/trigger` | 새 스캔 실행 | 유지 |
| `POST /api/ai1/results` | AI1 결과 수신 | 유지하되 필드 확장 필요 |
| `POST /api/ai2/scenarios` | AI2 체인 시나리오 수신 | 유지하되 `chain_scenario_id`, `attack_chain`, `manual_validation_guide` 구조 기준 |
| `POST /api/scans/{scan_id}/pentest` | Red Team 검증 결과 저장 | 유지 |

### 2.2 현재 프론트 더미 데이터 export

현재 `src/data/dummyData.js`는 다음 데이터를 사용한다.

| Export | 현재 의미 | 권장 API/데이터 소스 |
|---|---|---|
| `scanSummary` | 선택된 스캔 요약 | `GET /api/scans` item 또는 detail summary |
| `violations` | AI1 violated 결과 + UI 메타데이터 | AI1 result bundle 중 `status == violated` |
| `severityDistribution` | severity별 위반 수 | `violations`에서 파생 |
| `zoneViolations` | zone별 위반 수 | `violations` 또는 `invariant_impact.items`에서 파생 |
| `typeViolations` | 불변식 type별 위반 수 | invariant metadata 병합 후 파생 |
| `attackChains` | AI2 체인 | AI2 chain scenario |
| `mitreMapping` | MITRE 매핑 | `violations`와 `attackChains.mitre_attack_flow`에서 파생 |
| `pentestResults` | Red Team 결과 | `POST /api/scans/{scan_id}/pentest` |
| `coverage` | 공격 단계별 커버리지 | `violations` weight 기반 파생 |
| `assets` | 자산 목록 | Asset registry summary의 `assets` |
| `assetHistory` | 월별 자산 추세 | Asset registry snapshot 누적 데이터 |
| `assetEvents` | 자산 이벤트 | Asset change feed의 `changes` |
| `assetPolicies` | 정책 위반 요약 | `invariant_impact.items`와 정책 메타데이터에서 파생 |
| `remediations` | 조치 항목 | invariant metadata와 violated 결과에서 파생 |
| `softwareAssets` | 소프트웨어 자산 | optional, 현재 핵심 아님 |
| `credentialAssets` | 인증정보 자산 | optional, 현재 핵심 아님 |
| `apiAssets` | API 자산 | `assets` 중 `asset_type=api_service` 또는 `component_type=application_api` |
| `evidenceEvents` | 정규화 Evidence 탐색 | Evidence pack의 `evidence` |
| `evidenceTypeCoverage` | event_type별 수집 상태 | 완성본 event_type 목록과 실제 evidence count 비교 |
| `serviceAssets` | 서버 내 서비스 목록 | Asset registry의 `services` |
| `identityAccessAssets` | 계정/권한/credential 상태 | `account_state_event`, `privileged_access_state`, `identity_event` |
| `scanList` | 스캔 목록 | `GET /api/scans` |
| `scanDetails` | 스캔 상세 | `GET /api/scans/{scan_id}/details` |

## 3. Argos 통합 데이터 구조

Argos 보안 시스템은 중앙 보안 서비스에서 수집, 정규화, AI 판단, 자산 영향 분석 결과를 만든다. 프론트는 내부 파일명에 의존하지 않고, 아래 논리 payload가 API로 제공된다는 전제로 구현한다.

### 3.1 Dashboard adapter payload

```text
Dashboard summary
Asset registry summary
Asset change feed
Invariant impact summary
```

### 3.2 AI 및 Evidence payload

```text
AI1 invariant result bundle
AI1 coverage report
AI2 chain scenario
Evidence pack
Asset registry snapshot
```

### 3.3 핵심 payload

프론트 API에는 내부 schema 이름을 직접 노출하지 않는다. 내부 collector, normalizer, AI service가 검증용 schema version을 관리하더라도 `GET /api/scans`와 `GET /api/scans/{scan_id}/details` 응답에서는 아래 payload 역할과 필드 구조만 안정적으로 제공한다.

| Payload | 목적 |
|---|---|
| Dashboard summary | 전체 KPI |
| Asset registry summary | 대시보드용 자산 목록 |
| Asset change feed | 자산 변경 이력 |
| Invariant impact summary | 불변식 위반과 자산 영향 연결 |
| AI1 invariant result bundle | AI1 불변식 판단 결과 |
| AI1 coverage report | 아직 공식 판단하지 않는 불변식의 증거 gap |
| AI2 chain scenario | AI2 체인 시나리오 |
| Evidence pack | 정규화 Evidence |
| Asset registry snapshot | 지속 자산 registry |

### 3.4 완성본 기준 필드 계약

현재 1차 수집 범위에 일부 필드가 없더라도, 프론트 타입과 화면은 아래 필드를 모두 수용해야 한다.

#### Evidence 공통 필드

| 필드 | 의미 | 화면 사용 |
|---|---|---|
| `evidence_id` | Evidence stable id | 상세 drill-down, AI1 근거 연결 |
| `timestamp` | 관측 시각 | timeline |
| `trace_id` | 요청/체인 흐름 id | gateway/API/data 연결 |
| `request_id` | 단일 요청 id | 요청 상세 |
| `event_category` | `attack_execution` 또는 `environment_state` | 이벤트 분류 필터 |
| `producer.vm` | 이벤트 생성 VM | VM 필터 |
| `producer.component_id` | 이벤트 생성 컴포넌트 | 서비스 필터 |
| `producer.component_type` | 컴포넌트 유형 | 서비스 유형 필터 |
| `producer.zone` | trust boundary | zone 필터 |
| `producer.asset_id` | 이벤트 발생 자산 | 자산 연결 |
| `producer.service_id` | 이벤트 발생 서비스 | 서비스 연결 |
| `evidence_type` | 정규화 Evidence 유형 | evidence type 필터 |
| `observed` | event_type별 원 관찰 필드 | Evidence 상세의 핵심 원본 |
| `actor` | 행위자 요약 | 사용자/계정 탐색 |
| `token` | JWT/토큰 요약 | 토큰 관련 불변식 탐색 |
| `access` | 접근/인가/조회 요약 | endpoint, decision 필터 |
| `asset` | 접근 대상 자산/resource 요약 | 영향 자산 탐색 |
| `control` | 통제 수행 여부 요약 | owner check, rate limit, alert 필터 |
| `raw_ref` | 원본 로그 참조 | 원본 로그 위치 추적 |
| `metadata` | normalizer 부가 정보 | 디버깅/확장 |

#### event_type별 observed 필드

| event_type | 담당 의미 | 프론트에서 보여줄 핵심 observed 필드 |
|---|---|---|
| `account_state_event` | 퇴직자, 계정, credential 상태 | `employment_status`, `account_status`, `credential_status`, `active_session_count`, `groups` |
| `privileged_access_state` | 개발자, 관리자 권한 상태 | `production_secret_access_allowed`, `production_customer_data_access_allowed`, `admin_role`, `allowed_zones` |
| `key_management_state` | JWT 서명키 관리 상태 | `key_id`, `key_type`, `key_status`, `last_rotated_at`, `approved_storage`, `key_rotation_completed` |
| `token_policy_state` | JWT 검증 정책 상태 | `auth_method`, `algorithm`, `validate_signature`, `validate_iss`, `validate_aud`, `validate_exp`, `validate_jti_registry`, `validate_revocation`, `validate_kid_active` |
| `token_validation_event` | 개별 JWT 검증 결과 | `signature_valid`, `issued_by_auth_server`, `token_jti`, `token_kid`, `token_iss`, `token_aud`, `revoked` |
| `api_authorization_event` | API 인가 판단 결과 | `actor_id`, `token_sub`, `token_tenant`, `resource_id`, `resource_owner_id`, `resource_tenant_id`, `owner_check_performed`, `tenant_check_performed`, `authz_service_used`, `authorization_decision`, `status_code` |
| `gateway_access_event` | DMZ/API Gateway 접근 | `source_ip`, `source_zone`, `endpoint`, `method`, `internal_path_requested`, `internal_path_blocked`, `waf_action`, `status`, `upstream` |
| `network_policy_state` | DMZ 네트워크 정책 상태 | `external_access_to_internal_api_allowed`, `default_internal_path_action`, `allowed_source_zones`, `firewall_rule_refs` |
| `data_access_event` | DB/Object 조회 결과 | `resource_id`, `resource_owner_id`, `resource_tenant_id`, `sensitive_field_types`, `row_count`, `table`, `decision` |
| `object_storage_access_event` | Object storage 접근 | `bucket`, `object_key_ref`, `action`, `decision`, `object_lock_enabled`, `resource_owner_id`, `resource_tenant_id` |
| `aggregation_state` | 대량, 순차, 분산 조회 탐지 결과 | `request_count`, `distinct_owner_count`, `distinct_tenant_count`, `distinct_device_count`, `sequential_id_pattern`, `risk_score`, `alert_created`, `rate_limited` |
| `log_trace_state` | 계층별 로그 연결 상태 | `gateway_log_present`, `api_log_present`, `data_log_present`, `object_log_present`, `missing_trace_layers` |
| `log_retention_state` | 로그 보존, 변조 방지 상태 | `retention_lock_enabled`, `log_deleted_after_incident`, `object_lock_enabled`, `fim_alert_created` |
| `device_auth_event` | IoT device identity/topic 권한 | `device_id`, `device_owner_id`, `device_tenant_id`, `topic`, `auth_decision`, `anonymous_allowed` |
| `deployment_event` | Gitea/Jenkins/배포 상태 | `pipeline_id`, `artifact_ref`, `commit_ref`, `requested_by`, `signature_verified`, `deployment_result` |
| `ota_event` | OTA target 접근/조회 | `device_id`, `target_version`, `requested_by`, `role`, `internal_token_valid`, `authorization_decision` |
| `signing_event` | Signing server 요청 | `key_id`, `build_id`, `requested_by`, `caller_ip`, `caller_ip_allowlisted`, `signing_result`, `key_material_exposed` |
| `key_management_event` | FIM/syscheck 키 변경 | `key_id`, `file_path_ref`, `change_type`, `permission_changed`, `fim_alert_created` |
| `wazuh_alert_event` | Wazuh rule alert | `wazuh_rule_id`, `wazuh_rule_level`, `wazuh_rule_groups`, `alert_description` |

프론트는 `observed`를 그대로 테이블/JSON detail에 보여줄 수 있어야 한다. 단, raw token, secret, password, private key, 개인정보 원문은 표시하지 않는다. 정상 데이터에는 원문이 들어오면 안 되고, 들어오면 UI에서도 redaction 경고로 처리한다.

## 4. 필드 비교표

### 4.1 Scan list

프론트의 `GET /api/scans` 구조는 유지한다.

| 현재 프론트 필드 | Argos 기준 필드 | 처리 |
|---|---|---|
| `scan_id` | `snapshot_id` 기반으로 생성 | 유지 |
| `scanned_at` | `generated_at` 또는 `created_at` | 유지 |
| `status` | `completed`, `running`, `failed` | 유지 |
| `metrics.score` | `violated` severity 기반 계산 | 유지 |
| `metrics.total_violations` | `violated_invariant_count` | 유지 |
| `metrics.critical_high` | `violations` 중 Critical/High count | 유지 |
| `metrics.attack_chains` | AI2 scenario count | 유지 |
| `metrics.vulnerable_asset_count` | `invariant_impact` 영향 자산 수 | 유지 |
| `metrics.patch_rate` | optional | 없으면 `null` 또는 0 |

### 4.2 AI1 violation item

| 현재 프론트 필드 | Argos 기준 필드 | 처리 |
|---|---|---|
| `id` | `invariant_id` | rename, `id`는 UI alias로만 허용 |
| `result_id` | `result_id` | 유지 |
| `invariant_id` | `invariant_id` | 유지 |
| `confidence` | `confidence` | 유지 |
| `evidence_ids` | `evidence_ids` | 유지, 핵심 |
| `asset_ids` | `asset_ids` | 유지, 핵심 |
| `status` | `status` | 유지, `applied` 또는 `violated` |
| `violation_reason` | `violation_reason` | 유지, 핵심 |
| `summary` | `summary` | 유지 |
| `reason` | `reason` | 유지 |
| `current_environment_testable` | `current_environment_testable` | 유지 |
| `testability_reason` | `testability_reason` | 유지 |
| `created_at` | `created_at` | 유지 |
| `detected_at` | `created_at` | 제거 또는 alias |
| `server_zone` | `zone` | rename |
| `description` | invariant metadata 또는 `summary` | 유지 |
| `severity` | `severity` | UI에서는 `Critical/High/Medium/Low`, 원본은 lowercase 허용 |
| `type` | invariant metadata | 유지 |
| `attack_phase` | invariant metadata | 유지 |
| `mitre_tactic` | invariant metadata | 유지 |
| `mitre_technique` | invariant metadata | 유지 |
| `weight` | invariant metadata | 유지 |
| `invariant_source` | invariant metadata | 유지 |
| `remediation` | invariant metadata | 유지 |
| `priority` | invariant metadata | 유지 |

### 4.3 Asset item

| 현재 프론트 필드 | Argos 기준 필드 | 처리 |
|---|---|---|
| `id` | `asset_id` | rename |
| `name` | `asset_name` | rename, UI alias로 `name` 허용 |
| `type` | `asset_type` | rename |
| `segment` | `zone` 또는 `exposure` | `zone` 우선 |
| `zone` | `zone` | 유지 |
| `ip` | `ip_hint` | rename |
| `os` | optional | 없으면 표시하지 않음 |
| `os_age` | optional | 유지 가능 |
| `online_status` | optional | registry 상태와 별개 |
| `cvss_max` | optional | 현재 핵심 아님 |
| `patch_status` | optional | 현재 핵심 아님 |
| `edr` | optional | 현재 핵심 아님 |
| `av` | optional | 현재 핵심 아님 |
| `managed` | optional | 현재 핵심 아님 |
| `exposed` | `exposure` | `exposure` 우선 |
| `privilege` | optional | 현재 핵심 아님 |
| `violation_ids` | `related_invariant_ids` | rename |
| `last_seen` | `last_seen` | 유지 |
| 없음 | `asset_category` | 추가 필요 |
| 없음 | `observation_status` | 추가 필요 |
| 없음 | `criticality` | 추가 필요 |
| 없음 | `data_classes` | 추가 필요 |
| 없음 | `linked_services` | 추가 필요 |
| 없음 | `observed_services` | 추가 필요 |
| 없음 | `all_services` | 추가 필요 |
| 없음 | `evidence_refs` | 추가 필요 |
| 없음 | `observed_sources` | 추가 필요 |
| 없음 | `kisa_sheets` | 추가 필요 |
| 없음 | `related_invariant_ids` | 추가 필요 |
| 없음 | `record_hash` | 추가 필요 |

### 4.4 Service item

서버 관련 자산을 사람이 직접 파악하려면 서비스 목록이 별도 구조로 필요하다. 기존 프론트에는 이 구조가 부족하므로 `AssetSection` 안에 서비스 탭으로 추가한다.

| Argos 기준 필드 | 의미 |
|---|---|
| `service_id` | 서비스 stable id |
| `name` | 서비스 표시명 |
| `owning_asset` | 소유/대표 자산 id |
| `vm` | 실행 VM |
| `zone` | 실행 zone |
| `component_type` | `application_api`, `database`, `siem`, `state_collector` 등 |
| `deployment_ref` | 실제 배치 위치를 직접 노출하지 않는 서비스 배치 참조 |
| `log_source_refs` | 서비스가 남기는 로그 참조 목록 |
| `collected_by_wazuh` | Wazuh 수집 여부 |
| `observation_status` | expected/observed/expected_and_observed/unregistered_service_candidate |

### 4.5 Asset impact item

이 필드는 기존 프론트에는 부족하다. 반드시 추가해야 한다.

| Argos 기준 필드 | 의미 |
|---|---|
| `invariant_id` | 어떤 불변식 위반인지 |
| `result_id` | AI1 result id |
| `status` | `violated` |
| `violation_reason` | 위반 사유 |
| `severity` | 위험도 |
| `evidence_ids` | 근거 Evidence |
| `affected_registry_asset_ids` | 영향받는 registry 자산 |
| `affected_resource_ids` | 고객, 기기, 영상 등 업무 resource |
| `affected_services` | 영향받는 서비스 |
| `affected_zones` | 영향받는 zone |
| `summary` | UI 표시 요약 |

### 4.6 Evidence event item

불변식 위반 여부를 사람이 직접 추적하려면 정규화 Evidence 목록도 탐색할 수 있어야 한다. 이 화면은 `Evidence Store` 또는 `AssetSection`의 상세 탭으로 추가한다.

| Argos 기준 필드 | 의미 |
|---|---|
| `evidence_id` | Evidence stable id |
| `timestamp` | 관측 시각 |
| `trace_id` | 흐름 연결 id |
| `request_id` | 요청 id |
| `event_category` | `attack_execution` 또는 `environment_state` |
| `evidence_type` | 정규화 event type |
| `producer.vm` | 발생 VM |
| `producer.asset_id` | 발생 자산 |
| `producer.service_id` | 발생 서비스 |
| `observed` | event_type별 원 관찰값 |
| `actor.actor_id` | 행위자 |
| `access.endpoint` | 접근 endpoint |
| `access.decision` | allow/deny/observed |
| `asset.asset_id` | 접근 대상 resource |
| `control.*` | 통제 수행 여부 |
| `raw_ref.location` | 원본 로그 위치 |
| `raw_ref.log_id` | 원본 로그 참조 id |

### 4.7 AI2 chain item

구형 `nodes/edges/kill_chain/procedures` 형식은 제거한다. AI2는 `chain_scenario_id`, `scenario_basis`, `related_invariants`, `attack_chain`, `mitre_attack_flow`, `manual_validation_guide` 구조를 사용한다.

| 현재 프론트 필드 | Argos 기준 필드 | 처리 |
|---|---|---|
| `chain_scenario_id` | `chain_scenario_id` | 유지 |
| `created_at` | `created_at` | 유지 |
| `title` | `title` | 유지 |
| `source_bundle_id` | `source_bundle_id` | 유지 |
| `risk_level` | `risk_level` | 유지 |
| `scenario_basis` | `scenario_basis` | 유지 |
| `current_environment_testable` | `current_environment_testable` | 유지 |
| `testability_reason` | `testability_reason` | 유지 |
| `related_invariants` | `related_invariants` | 유지 |
| `attack_chain` | `attack_chain` | 유지 |
| `mitre_attack_flow` | `mitre_attack_flow` | 유지 |
| `manual_validation_guide` | `manual_validation_guide` | 유지 |
| `nodes` | 없음 | 제거 |
| `edges` | 없음 | 제거 |
| `kill_chain` | `mitre_attack_flow`로 대체 | 제거 |
| `procedures` | `manual_validation_guide.steps`로 대체 | 제거 |

## 5. 필드 rename 규칙

프론트 코드는 아래 rename 기준을 따른다.

| 기존 이름 | 새 기준 이름 | 비고 |
|---|---|---|
| `assets.id` | `asset_id` | stable key |
| `assets.name` | `asset_name` | UI 표시에는 `name` alias 가능 |
| `assets.type` | `asset_type` | `type`은 JS에서 모호함 |
| `assets.ip` | `ip_hint` | IP는 마지막 octet이 바뀔 수 있어 stable key가 아님 |
| `assets.violation_ids` | `related_invariant_ids` | 위반 불변식 연결 |
| `violations.id` | `invariant_id` | 구형 alias 제거 |
| `violations.server_zone` | `zone` | zone 명칭 통일 |
| `violations.detected_at` | `created_at` | AI1 생성 시각 기준 |
| `violation_ids` | `related_invariant_ids` | 자산/정책/API 모두 동일 |
| `attackChains.nodes` | 사용 금지 | 구형 체인 |
| `attackChains.edges` | 사용 금지 | 구형 체인 |

## 6. 제거, optional, 추가 필드

### 6.1 제거해야 할 필드

아래 필드는 새 데이터 계약에서 제거한다.

```text
구형 INV-### 더미 ID
AI2 nodes
AI2 edges
AI2 kill_chain
AI2 procedures
실제 evidence와 연결되지 않는 mock-only 설명
실제 존재하지 않는 임의 IP/MAC/고객 데이터 원문
```

불변식 ID는 반드시 다음 형태를 사용한다.

```text
INV-STD-01 ... INV-STD-14
INV-ARG-01 ... INV-ARG-08
```

### 6.2 optional로 유지 가능한 필드

아래 필드는 화면 품질을 위해 남겨도 되지만, 현재 Argos AI1/AI2 핵심 흐름의 필수 필드는 아니다.

```text
cvss_max
edr
av
os
os_age
patch_status
privilege
managed
online_status
softwareAssets
credentialAssets
apiAssets
```

이 값이 없으면 UI는 빈 값, `unknown`, `null`, 또는 표시 생략으로 처리한다.

### 6.3 반드시 추가해야 할 필드

```text
snapshot_id
company_id
asset_id
asset_name
asset_type
asset_category
observation_status
criticality
evidence_ids
evidence_refs
observed_services
all_services
observed_sources
asset_ids
violation_reason
current_environment_testable
testability_reason
affected_registry_asset_ids
affected_resource_ids
affected_services
affected_zones
kisa_sheets
record_hash
related_invariant_ids
event_category
observed
producer.vm
producer.asset_id
producer.service_id
raw_ref.location
raw_ref.log_id
```

## 7. 권장 API 응답 구조

프론트는 기존 `scan/detail` 구조를 유지하고, 내부 데이터만 최신 필드로 채운다.

### 7.1 GET /api/scans

```json
[
  {
    "scan_id": "SCAN-20260506-001",
    "snapshot_id": "asset-snapshot-20260506050856",
    "scanned_at": "2026-05-06T05:08:56.267746Z",
    "status": "completed",
    "metrics": {
      "score": 58,
      "total_violations": 6,
      "critical_high": 6,
      "attack_chains": 1,
      "vulnerable_asset_count": 3,
      "patch_rate": null
    }
  }
]
```

### 7.2 GET /api/scans/{scan_id}/details

```json
{
  "scan_id": "SCAN-20260506-001",
  "snapshot_id": "asset-snapshot-20260506050856",
  "generated_at": "2026-05-06T05:08:56.267746Z",
  "summary": {
    "total_violations": 6,
    "critical_high": 6,
    "attack_chains": 1,
    "asset_count": 36,
    "service_count": 36
  },
  "evidenceTypeCoverage": [
    {
      "evidence_type": "account_state_event",
      "expected_in_final": true,
      "collected_count": 0,
      "collection_status": "not_collected_yet"
    },
    {
      "evidence_type": "api_authorization_event",
      "expected_in_final": true,
      "collected_count": 3,
      "collection_status": "collected"
    },
    {
      "evidence_type": "token_policy_state",
      "expected_in_final": true,
      "collected_count": 1,
      "collection_status": "collected"
    }
  ],
  "evidenceTypeCoverage": [
    {
      "evidence_type": "api_authorization_event",
      "expected_in_final": true,
      "collected_count": 3,
      "collection_status": "collected"
    },
    {
      "evidence_type": "log_retention_state",
      "expected_in_final": true,
      "collected_count": 0,
      "collection_status": "not_collected_yet"
    }
  ],
  "violations": [],
  "severityDistribution": [],
  "zoneViolations": [],
  "typeViolations": [],
  "attackChains": [],
  "mitreMapping": [],
  "pentestResults": [],
  "coverage": {},
  "assets": [],
  "services": [],
  "evidenceEvents": [],
  "assetEvents": [],
  "assetPolicies": [],
  "remediations": [],
  "softwareAssets": [],
  "credentialAssets": [],
  "apiAssets": [],
  "invariantImpact": []
}
```

## 8. 더미 데이터 예시

아래 예시는 프론트 mock data에 바로 넣어 테스트할 수 있는 최소 형태다. 실제 운영에서는 `dashboard_adapter`가 같은 구조로 생성한다.

### 8.1 AI1 violation item

```json
{
  "result_id": "ai1-s1-inv-std-05-001",
  "created_at": "2026-05-06T05:08:56.207481Z",
  "invariant_id": "INV-STD-05",
  "confidence": 0.96,
  "severity": "High",
  "evidence_ids": ["evd-s1-token-validation-001", "evd-s1-token-policy-001"],
  "asset_ids": ["APP-AUTH-001", "APP-WAS-001"],
  "status": "violated",
  "violation_reason": "clear_violation",
  "summary": "정상 발급 절차가 확인되지 않은 토큰 요청이 allow로 처리되었다.",
  "reason": "issued_by_auth_server=false인 요청이 200/allow로 기록되어 토큰 발급 절차 검증 불변식을 위반한다.",
  "current_environment_testable": true,
  "testability_reason": "승인된 Scenario 1 검증 환경에서 token policy, token validation, API authorization Evidence를 수집할 수 있다.",
  "description": "정상 발급 절차 없는 JWT/토큰 접근 금지",
  "zone": "ops",
  "type": "접근제어",
  "attack_phase": "초기침투",
  "mitre_tactic": "TA0001",
  "mitre_technique": "T1078",
  "weight": 10,
  "invariant_source": "fixed",
  "remediation": "JWT issuer, audience, jti, revocation 검증을 강제한다.",
  "priority": "즉시"
}
```

### 8.2 Asset item

```json
{
  "asset_id": "APP-WAS-001",
  "asset_name": "fastapi was",
  "name": "fastapi was",
  "asset_type": "application_audit_log",
  "type": "application_audit_log",
  "asset_category": "server",
  "category": "server",
  "observation_status": "unregistered_asset_candidate",
  "status": "unregistered_asset_candidate",
  "zone": "ops",
  "vm": "argos-ops",
  "ip_hint": "10.10.3.2",
  "criticality": "unknown",
  "exposure": "unknown",
  "data_classes": [],
  "linked_services": ["SVC-WAS-001"],
  "observed_services": ["SVC-WAS-001"],
  "all_services": ["SVC-WAS-001"],
  "evidence_refs": ["evd-s1-api-authz-001", "evd-s1-token-policy-001", "evd-s1-aggregation-001"],
  "evidence_count": 3,
  "observed_sources": ["wazuh"],
  "kisa_sheets": ["1. 서버"],
  "first_seen": "2026-05-05T10:00:00+09:00",
  "last_seen": "2026-05-05T10:01:00+09:00",
  "record_hash": "0c8f137bfa7e0e4f",
  "related_invariant_ids": ["INV-STD-07", "INV-ARG-01", "INV-ARG-03"]
}
```

### 8.3 Service item

```json
{
  "service_id": "SVC-WAS-001",
  "name": "fastapi was",
  "owning_asset": "APP-WAS-001",
  "vm": "argos-ops",
  "zone": "ops",
  "component_type": "application_api",
  "deployment_ref": "deploy://argos-ops/services/was",
  "log_source_refs": ["log-source://argos-ops/api-audit"],
  "collected_by_wazuh": true,
  "observation_status": "unregistered_service_candidate"
}
```

### 8.4 Evidence event item

```json
{
  "evidence_id": "evd-s1-api-authz-001",
  "timestamp": "2026-05-05T10:00:00+09:00",
  "trace_id": "trc-s1-001",
  "request_id": "req-s1-001",
  "event_category": "attack_execution",
  "producer": {
    "vm": "argos-ops",
    "component_id": "argos-ops-api-audit",
    "component_type": "application_audit_log",
    "zone": "ops",
    "asset_id": "APP-WAS-001",
    "service_id": "SVC-WAS-001"
  },
  "evidence_type": "api_authorization_event",
  "observed": {
    "actor_id": "customer_a",
    "actor_role": "user",
    "token_sub": "customer_a",
    "token_tenant": "tenant-a",
    "token_jti": "jti-issued-001",
    "token_kid": "argos-signing-key-202605",
    "signature_valid": true,
    "issued_by_auth_server": true,
    "endpoint": "/api/devices/device-b",
    "method": "GET",
    "resource_type": "device",
    "resource_id": "device-b",
    "resource_owner_id": "customer_b",
    "resource_tenant_id": "tenant-b",
    "owner_check_performed": false,
    "tenant_check_performed": false,
    "authz_service_used": false,
    "authorization_decision": "allow",
    "status_code": 200
  },
  "actor": {
    "actor_id": "customer_a",
    "role": "user",
    "source_ip": "10.10.1.2",
    "source_ip_class": "internal"
  },
  "token": {
    "token_present": true,
    "token_sub": "customer_a",
    "token_tenant": "tenant-a",
    "kid": "argos-signing-key-202605",
    "jti": "jti-issued-001",
    "signature_valid": true,
    "issued_by_auth_server": true,
    "revoked": false
  },
  "access": {
    "action": "authorization_audit",
    "endpoint": "/api/devices/device-b",
    "method": "GET",
    "target_identifier": "device-b",
    "decision": "allow",
    "status_code": 200
  },
  "asset": {
    "asset_id": "device-b",
    "asset_type": "device",
    "owner_id": "customer_b",
    "tenant_id": "tenant-b"
  },
  "control": {
    "owner_check_performed": false,
    "tenant_check_performed": false,
    "authz_service_used": false
  },
  "raw_ref": {
    "source": "wazuh",
    "agent": "argos-ops",
    "location": "/var/log/argos/api-audit.log",
    "log_id": "wazuh-api-authz-001"
  },
  "metadata": {
    "redaction": "no_raw_secret_or_pii"
  }
}
```

### 8.5 Asset impact item

```json
{
  "invariant_id": "INV-ARG-03",
  "result_id": "ai1-s1-inv-arg-03-001",
  "status": "violated",
  "violation_reason": "clear_violation",
  "severity": "high",
  "evidence_ids": ["evd-s1-api-authz-001", "evd-s1-data-access-001"],
  "affected_registry_asset_ids": ["APP-WAS-001"],
  "affected_resource_ids": ["device-b", "video-b"],
  "affected_services": ["SVC-WAS-001"],
  "affected_zones": ["ops"],
  "summary": "요청 URL의 resource id 변경으로 타인 resource가 반환될 수 있는 상태다."
}
```

### 8.6 AI2 chain scenario

```json
{
  "chain_scenario_id": "chain-s1-jwt-policy-cross-tenant-access-001",
  "created_at": "2026-05-06T05:08:56.273762Z",
  "title": "Scenario 1 chain: weak token policy to cross-tenant object access",
  "source_bundle_id": "bundle-s1-jwt-policy-cross-tenant-access-001",
  "risk_level": "high",
  "scenario_basis": {
    "status": "violated",
    "violation_reason": "clear_violation",
    "summary": "정상 발급 절차가 확인되지 않은 토큰 요청이 allow로 처리되었다."
  },
  "current_environment_testable": true,
  "testability_reason": "승인된 Scenario 1 검증 환경에서 DMZ gateway, API, data access, aggregation detector Evidence가 동일 trace_id로 연결된다.",
  "related_invariants": [
    "INV-STD-05",
    "INV-STD-07",
    "INV-STD-09",
    "INV-ARG-01",
    "INV-ARG-03",
    "INV-ARG-06"
  ],
  "attack_chain": [
    "승인 검증 요청이 argos-dmz gateway를 거쳐 argos-ops API로 전달된다.",
    "argos-ops API가 토큰 발급 출처 또는 토큰 생명주기 상태를 충분히 검증하지 못한 상태를 관측한다.",
    "같은 요청 흐름에서 owner/tenant가 다른 device 또는 video resource 접근이 allow로 기록된다.",
    "argos-data 접근 로그와 aggregation detector가 다수 owner/tenant/device 조회 패턴을 보강한다.",
    "AI2는 위 관찰 사실을 하나의 검증 가능한 체인 후보로 묶고, 실제 공격 절차 대신 승인 검증 기준만 제공한다."
  ],
  "mitre_attack_flow": [
    {
      "order": 1,
      "tactic": "Initial Access",
      "step": "Authorized validation request enters through the DMZ gateway.",
      "related_invariants": ["INV-STD-10"],
      "reason": "gateway trace_id and API trace_id correlation prove the observed path."
    },
    {
      "order": 2,
      "tactic": "Credential Access",
      "step": "Token policy state lacks complete lifecycle validation.",
      "related_invariants": ["INV-STD-05"],
      "reason": "token_policy_state shows missing jti/revocation validation controls."
    },
    {
      "order": 3,
      "tactic": "Collection",
      "step": "Cross-owner or cross-tenant object read is allowed in the approved validation flow.",
      "related_invariants": ["INV-STD-07", "INV-ARG-01", "INV-ARG-03"],
      "reason": "API authorization evidence records allow decisions for mismatched ownership and tenant."
    }
  ],
  "manual_validation_guide": {
    "goal": "AI2가 만든 체인 후보가 승인된 검증 범위에서 재현 가능한지 확인한다.",
    "steps": [
      "Scenario 1 검증 스캔을 실행한다.",
      "동일 trace_id가 gateway, api, data evidence에 연결되는지 확인한다.",
      "AI1 violated 결과가 AI2 related_invariants에 포함되는지 확인한다."
    ],
    "success_criteria": [
      "AI2 체인이 AI1 violated 결과만 근거로 사용한다.",
      "각 체인 단계가 evidence_id 또는 invariant_id와 연결된다.",
      "raw token, raw secret, 개인정보 원문이 포함되지 않는다."
    ],
    "evidence_to_collect": [
      "Gateway access Evidence",
      "API authorization Evidence",
      "AI1 invariant result bundle",
      "AI2 chain scenario"
    ],
    "safety_boundary": [
      "approved validation accounts and approved validation resources only",
      "no raw token is generated, stored, replayed, or requested",
      "no exploit payloads, no exploit instructions, and no production data access"
    ]
  }
}
```

### 8.7 Red Team validation result

```json
{
  "scenario_id": "chain-s1-jwt-policy-cross-tenant-access-001",
  "test_id": "rt-20260506-001",
  "tester": "redteam-operator-01",
  "tested_at": "2026-05-06T06:00:00Z",
  "related_invariants": ["INV-STD-05", "INV-STD-07", "INV-ARG-01", "INV-ARG-03"],
  "target_assets": [
    {
      "asset_type": "application_api",
      "asset_id": "APP-WAS-001"
    },
    {
      "asset_type": "auth_service",
      "asset_id": "APP-AUTH-001"
    }
  ],
  "overall_verdict": "partially_reproduced",
  "narrative": {
    "attack_input_and_process": "AI2 체인 후보를 승인 검증 계정과 승인 검증 resource로 재현했다.",
    "observed_result": "토큰 정책 상태와 cross-resource 접근 evidence가 연결되는 것을 확인했다.",
    "impact_assessment": "실제 고객 데이터 접근 없이 tenant/owner 검증 gap을 확인했다.",
    "evidence_description": "검증 근거는 evidence_id, trace_id, AI1 result_id로만 기록했다.",
    "additional_notes": "운영 데이터, raw token, secret 원문은 사용하지 않았다."
  }
}
```

### 8.8 Complete scan detail dummy

```json
{
  "scan_id": "SCAN-20260506-001",
  "snapshot_id": "asset-snapshot-20260506050856",
  "generated_at": "2026-05-06T05:08:56.267746Z",
  "summary": {
    "total_violations": 6,
    "critical_high": 6,
    "attack_chains": 1,
    "asset_count": 36,
    "service_count": 36
  },
  "violations": [
    {
      "result_id": "ai1-s1-inv-std-05-001",
      "created_at": "2026-05-06T05:08:56.207481Z",
      "invariant_id": "INV-STD-05",
      "confidence": 0.96,
      "severity": "High",
      "evidence_ids": ["evd-s1-token-validation-001", "evd-s1-token-policy-001"],
      "asset_ids": ["APP-AUTH-001", "APP-WAS-001"],
      "status": "violated",
      "violation_reason": "clear_violation",
      "summary": "정상 발급 절차가 확인되지 않은 토큰 요청이 allow로 처리되었다.",
      "reason": "issued_by_auth_server=false인 요청이 200/allow로 기록되어 토큰 발급 절차 검증 불변식을 위반한다.",
      "current_environment_testable": true,
      "testability_reason": "승인된 Scenario 1 검증 환경에서 token policy, token validation, API authorization Evidence를 수집할 수 있다.",
      "zone": "ops",
      "type": "접근제어",
      "attack_phase": "초기침투",
      "mitre_tactic": "TA0001",
      "mitre_technique": "T1078",
      "weight": 10,
      "invariant_source": "fixed",
      "remediation": "JWT issuer, audience, jti, revocation 검증을 강제한다.",
      "priority": "즉시"
    }
  ],
  "assets": [
    {
      "asset_id": "APP-WAS-001",
      "asset_name": "fastapi was",
      "name": "fastapi was",
      "asset_type": "application_audit_log",
      "type": "application_audit_log",
      "asset_category": "server",
      "category": "server",
      "observation_status": "unregistered_asset_candidate",
      "status": "unregistered_asset_candidate",
      "zone": "ops",
      "vm": "argos-ops",
      "ip_hint": "10.10.3.2",
      "criticality": "unknown",
      "exposure": "unknown",
      "data_classes": [],
      "linked_services": ["SVC-WAS-001"],
      "observed_services": ["SVC-WAS-001"],
      "all_services": ["SVC-WAS-001"],
      "evidence_refs": ["evd-s1-api-authz-001", "evd-s1-token-policy-001", "evd-s1-aggregation-001"],
      "evidence_count": 3,
      "kisa_sheets": ["1. 서버"],
      "record_hash": "0c8f137bfa7e0e4f",
      "related_invariant_ids": ["INV-STD-07", "INV-ARG-01", "INV-ARG-03"]
    }
  ],
  "services": [
    {
      "service_id": "SVC-WAS-001",
      "name": "fastapi was",
      "owning_asset": "APP-WAS-001",
      "vm": "argos-ops",
      "zone": "ops",
      "component_type": "application_api",
      "deployment_ref": "deploy://argos-ops/services/was",
      "log_source_refs": ["log-source://argos-ops/api-audit"],
      "collected_by_wazuh": true,
      "observation_status": "unregistered_service_candidate"
    }
  ],
  "evidenceEvents": [
    {
      "evidence_id": "evd-s1-api-authz-001",
      "timestamp": "2026-05-05T10:00:00+09:00",
      "trace_id": "trc-s1-001",
      "request_id": "req-s1-001",
      "event_category": "attack_execution",
      "producer": {
        "vm": "argos-ops",
        "component_id": "argos-ops-api-audit",
        "component_type": "application_audit_log",
        "zone": "ops",
        "asset_id": "APP-WAS-001",
        "service_id": "SVC-WAS-001"
      },
      "evidence_type": "api_authorization_event",
      "observed": {
        "authorization_decision": "allow",
        "resource_id": "device-b",
        "resource_owner_id": "customer_b",
        "resource_tenant_id": "tenant-b"
      },
      "raw_ref": {
        "source": "wazuh",
        "agent": "argos-ops",
        "location": "/var/log/argos/api-audit.log",
        "log_id": "wazuh-api-authz-001"
      }
    }
  ],
  "invariantImpact": [
    {
      "invariant_id": "INV-ARG-03",
      "result_id": "ai1-s1-inv-arg-03-001",
      "status": "violated",
      "violation_reason": "clear_violation",
      "severity": "high",
      "evidence_ids": ["evd-s1-api-authz-001", "evd-s1-data-access-001"],
      "affected_registry_asset_ids": ["APP-WAS-001"],
      "affected_resource_ids": ["device-b", "video-b"],
      "affected_services": ["SVC-WAS-001"],
      "affected_zones": ["ops"],
      "summary": "요청 URL의 resource id 변경으로 타인 resource가 반환될 수 있는 상태다."
    }
  ],
  "attackChains": [
    {
      "chain_scenario_id": "chain-s1-jwt-policy-cross-tenant-access-001",
      "created_at": "2026-05-06T05:08:56.273762Z",
      "title": "Scenario 1 chain: weak token policy to cross-tenant object access",
      "source_bundle_id": "bundle-s1-jwt-policy-cross-tenant-access-001",
      "risk_level": "high",
      "scenario_basis": {
        "status": "violated",
        "violation_reason": "clear_violation",
        "summary": "정상 발급 절차가 확인되지 않은 토큰 요청이 allow로 처리되었다."
      },
      "current_environment_testable": true,
      "testability_reason": "승인된 Scenario 1 검증 환경에서 DMZ gateway, API, data access, aggregation detector Evidence가 동일 trace_id로 연결된다.",
      "related_invariants": ["INV-STD-05", "INV-STD-07", "INV-ARG-01", "INV-ARG-03"],
      "attack_chain": [
        "승인 검증 요청이 argos-dmz gateway를 거쳐 argos-ops API로 전달된다.",
        "owner/tenant가 다른 resource 접근이 allow로 기록된다.",
        "AI2는 위 관찰 사실을 검증 가능한 체인 후보로 묶는다."
      ],
      "mitre_attack_flow": [],
      "manual_validation_guide": {
        "goal": "AI2 체인 후보를 승인된 검증 범위에서 확인한다.",
        "steps": ["동일 trace_id의 evidence 연결을 확인한다."],
        "success_criteria": ["raw token, secret, 개인정보 원문이 포함되지 않는다."],
        "evidence_to_collect": ["AI1 invariant result bundle", "AI2 chain scenario"],
        "safety_boundary": [
          "approved validation accounts and approved validation resources only",
          "no raw token is generated, stored, replayed, or requested",
          "no exploit payloads, no exploit instructions, and no production data access"
        ]
      }
    }
  ],
  "pentestResults": [],
  "severityDistribution": [
    { "name": "Critical", "value": 0, "color": "#0C447C" },
    { "name": "High", "value": 6, "color": "#185FA5" },
    { "name": "Medium", "value": 0, "color": "#378ADD" },
    { "name": "Low", "value": 0, "color": "#85B7EB" }
  ],
  "zoneViolations": [
    { "zone": "ops", "count": 4 },
    { "zone": "security", "count": 2 }
  ],
  "typeViolations": [
    { "name": "접근제어", "value": 5, "color": "#0C447C" },
    { "name": "보안정책", "value": 1, "color": "#185FA5" }
  ],
  "mitreMapping": [],
  "coverage": {},
  "assetEvents": [],
  "assetPolicies": [],
  "remediations": [],
  "softwareAssets": [],
  "credentialAssets": [],
  "apiAssets": []
}
```

## 9. Migration checklist

프론트 팀원 에이전트는 아래 순서로 작업하면 된다.

```text
1. 기존 화면 구조와 메뉴는 유지한다.
2. src/data/dummyData.js의 구형 INV-### id를 INV-STD-*/INV-ARG-*로 교체한다.
3. assets 배열의 id/name/type/ip를 asset_id/asset_name/asset_type/ip_hint 기준으로 바꾼다.
4. 기존 UI에서 필요한 경우 name, id alias는 화면 표시용으로만 유지한다.
5. violations는 AI1 result 원본 필드를 중심으로 구성한다.
6. violation_reason, evidence_ids, asset_ids를 필수 표시 대상으로 추가한다.
7. attackChains는 `chain_scenario_id`, `scenario_basis`, `related_invariants`, `attack_chain`, `manual_validation_guide` 구조만 사용한다.
8. nodes/edges/kill_chain/procedures 기반 구형 체인 코드는 제거한다.
9. invariantImpact 섹션을 추가해 어떤 불변식이 어떤 자산/서비스/resource에 닿는지 보여준다.
10. assetEvents는 Asset change feed의 `changes`를 기준으로 만든다.
11. optional 필드는 데이터가 없을 때 화면이 깨지지 않게 null-safe 처리한다.
12. 운영 연동 시 VITE_API_BASE_URL을 central dashboard API로 지정한다.
13. AssetSection의 기존 하드웨어/소프트웨어/인증정보/API 탭을 제거하지 말고, 서버/서비스/Evidence/권한 탐색 탭을 추가한다.
14. 사람이 AI 없이도 `asset_id -> service_id -> evidence_id -> invariant_id` 순서로 직접 추적할 수 있게 상세 패널을 만든다.
15. AI1/AI2 결과는 자산 탐색 결과 위에 얹히는 보조 요약으로 표시한다.
```

## 10. Implementation note for frontend agent

프론트 에이전트는 이 문서를 기준으로 다음 방향으로 구현한다.

```text
화면 구조:
  기존 sia-purpleteam_dashboard 구조 유지

데이터 소스:
  개발 중에는 mock data
  운영 전환 시 GET /api/scans, GET /api/scans/{scan_id}/details

필드 우선순위:
  Argos 운영 데이터 계약 필드 > 기존 프론트 mock 필드

중요한 UI 표시:
  invariant_id
  status
  violation_reason
  evidence_ids
  asset_ids
  affected_services
  affected_resource_ids
  current_environment_testable
  testability_reason
```

AI1의 `violated`는 확정 침해가 아니라 AI2가 체인 노드로 사용할 위반 후보다. AI2가 체인을 만들고, Red Team이 승인된 검증 범위에서 그 체인을 검증한다. 따라서 대시보드 문구도 “공격 성공”보다 “검증 대상 체인 후보”, “불변식 위반 후보”, “레드팀 검증 필요” 쪽으로 표시하는 것이 맞다.
