# GCP AI 출력 데이터 프론트 서빙 계약서

작성 기준: GCP `argos-security` 현재 운영 API/AI Pack/DB 직접 확인  
최신 scan: `ai-run-20260511-092330`  
목적: 프론트 담당자가 화면을 새로 설계할 때, 어떤 API field를 사용하면 되는지와 그 field가 AI Pack 파일/DB 어디에서 왔는지 충돌 없이 확인하게 하는 문서다.

## 1. 결론
프론트는 서버 파일이나 DB를 직접 읽지 말고 **Backend API를 단일 계약면**으로 사용한다. 데이터 출처를 추적할 때만 AI Pack 파일 경로와 PostgreSQL 테이블을 참고한다.

- 현재 최신 scan은 `ai-run-20260511-092330`이다.
- 현재 detail summary는 `violations=29`, `invariants=56`, `applied=27`, `assets=133`, `services=32`, `official attackChains=1`이다.
- 현재 raw evidence는 `42,580` rows, `145,957,724` bytes다.
- 시나리오2 OTA/firmware/device lifecycle evidence는 아직 들어오지 않았다. 관련 필드는 아래 “시나리오2 확장 대비 field 계약”에 optional field로 설계해야 한다.
- 공식 MITRE mapping은 현재 `missing_or_insufficient_evidence` 상태다. `diagnosticMitreTacticMap`은 화면 보조/진단용으로만 쓰고 공식 Red Team 시나리오와 섞으면 안 된다.

## 2. 기준 경로
| 구분 | GCP path | 프론트 담당자 의미 |
| --- | --- | --- |
| raw_evidence | /opt/argos/security/evidence_output/argos-asset-evidence-v1.jsonl | 직접 읽지 말고 API/백엔드 계약 확인용 |
| ai_runtime_current | /opt/argos/security/ai_runtime/current | 직접 읽지 말고 API/백엔드 계약 확인용 |
| ai_runtime_runs | /opt/argos/security/ai_runtime/runs/{run_id} | 직접 읽지 말고 API/백엔드 계약 확인용 |
| ai_latest | /opt/argos/security/ai_runtime/dashboard_api/latest | 직접 읽지 말고 API/백엔드 계약 확인용 |
| backend | /opt/argos-backend | 직접 읽지 말고 API/백엔드 계약 확인용 |
| backend_main | /opt/argos-backend/main.py | 직접 읽지 말고 API/백엔드 계약 확인용 |
| backend_ingestion | /opt/argos-backend/ingestion.py | 직접 읽지 말고 API/백엔드 계약 확인용 |
| backend_scanner | /opt/argos-backend/scanner.py | 직접 읽지 말고 API/백엔드 계약 확인용 |
| frontend_source | /opt/argos-dashboard-source | 직접 읽지 말고 API/백엔드 계약 확인용 |
| frontend_dist | /opt/argos-dashboard/dist | 직접 읽지 말고 API/백엔드 계약 확인용 |
| postgres_db | postgresql://argos_app@127.0.0.1:5432/argos_security | 직접 읽지 말고 API/백엔드 계약 확인용 |

## 3. 데이터 흐름
```text
raw evidence JSONL
  -> AI Pack snapshot run
  -> /opt/argos/security/ai_runtime/dashboard_api/latest/*.json
  -> dashboard-db-ingestion-export.json
  -> PostgreSQL ingest
  -> /opt/argos-backend API
  -> frontend rendering
```

충돌 방지 우선순위:
1. 화면 표시 값은 `GET /api/scans`와 `GET /api/scans/{scan_id}/details`를 우선한다.
2. 같은 값이 AI Pack latest와 DB에 모두 있으면 API 응답을 우선한다.
3. evidence 원문 필드가 필요하면 프론트가 직접 파일을 읽지 말고 detail API의 `evidenceEvents` 또는 `violations[].evidence_details`에 노출된 값만 사용한다.
4. `/api/scans/trigger`는 legacy/mock 성격이므로 새 점검 버튼에서 사용하지 않는다. 새 점검은 `/api/scans/start`만 사용한다.

## 4. API 경로 전체 목록
| API | 프론트 사용 여부 | 용도 |
| --- | --- | --- |
| POST /api/ai1/results | 내부용 | AI1 ingestion 내부용 |
| POST /api/ai2/scenarios | 내부용 | AI2 ingestion 내부용 |
| GET /api/health | 권장 | 프론트 연결 상태/DB 상태 표시 |
| POST /api/ingest/db-ingestion | 사용 금지 | 운영자/백엔드용. 프론트에서 직접 호출 금지 |
| GET /api/invariants | 권장 | 불변식 catalog 관리 화면 |
| POST /api/invariants | 권장 | custom invariant 생성 |
| GET /api/scans | 권장 | 점검 목록과 최신 scan 선택 |
| POST /api/scans/start | 권장 | 스냅샷 점검 시작. 동시 실행 방지 포함 |
| GET /api/scans/start/status | 권장 | 점검 중 lock, elapsed, snapshot size 표시 |
| POST /api/scans/trigger | 사용 금지 | legacy/mock 성격. 새 점검 UI에서 사용 금지 |
| GET /api/scans/{scan_id}/ai1-trace | 권장 | AI1 판단 trace 상세/디버그용 |
| GET /api/scans/{scan_id}/details | 권장 | 대시보드 대부분의 데이터. 프론트 주 데이터 소스 |
| POST /api/scans/{scan_id}/pentest | 권장 | 레드팀 검증 결과 저장 |
| DELETE /api/scans/{scan_id}/pentest/{test_id} | 권장 | 레드팀 검증 결과 삭제 |

## 5. API와 AI Pack/DB 매핑
| 데이터 묶음 | 프론트 API | API field | AI Pack file | DB table | 현재 값/건수 |
| --- | --- | --- | --- | --- | --- |
| scan list/status | GET /api/scans, GET /api/scans/start/status | scan_id, scanned_at, status, asset_count, service_count, total_violations, attack_chains_count, snapshot_size_bytes, elapsed_seconds | summary.json, dashboard-db-ingestion-export.json | scans, scan_asset_snapshot | latest=ai-run-20260511-092330, scans=10, snapshot=138,538,773 bytes |
| summary KPI | GET /api/scans/{scan_id}/details | summary.total_violations, violated_invariant_count, applied_invariant_count, invariant_total, critical_high, attack_chains | summary.json, invariant-results.json, ai2-chain-scenarios.json | scans, violations, attack_chains | {"total_violations": 29, "violated_invariant_count": 29, "applied_invariant_count": 27, "invariant_total": 56, "critical_high": 15, "attack_chains": 1} |
| invariants | GET /api/scans/{scan_id}/details | invariants[] | invariant-catalog.json, fixed-invariants.json, custom-invariants.json, disabled-invariants.json | invariants | 56 |
| violations | GET /api/scans/{scan_id}/details | violations[] | invariant-results.json, ai1-context-packs.json, ai1-llm-reviews.json | violations, violation_evidence, violation_assets | 29 |
| violation evidence detail | GET /api/scans/{scan_id}/details | violations[].evidence_details, affected_assets, affected_services, affected_zones, missing_evidence_fields | dashboard-db-ingestion-export.json, ai1-context-packs.json | evidence_events, assets, services | 위반 상세 팝업의 핵심 근거 |
| assets/services | GET /api/scans/{scan_id}/details | assets[], services[] | assets.json, asset-invariant-impact.json, kisa-asset-inventory.json | assets, services, asset_services | assets=133, services=32 |
| attack chains | GET /api/scans/{scan_id}/details | attackChains[] | ai2-chain-scenarios.json | attack_chains, attack_chain_steps, attack_chain_invariants | 1 |
| diagnostic redteam candidates | GET /api/scans/{scan_id}/details | diagnosticRedteamCandidates[] | backend diagnostic fallback | 없음 또는 보강 계산 | 3 |
| MITRE official | GET /api/scans/{scan_id}/details | mitreTacticMap, mitreMapping | mitre-tactic-map.json | mitre_attack_flow, mitre_flow_invariants | status=missing_or_insufficient_evidence |
| MITRE diagnostic fallback | GET /api/scans/{scan_id}/details | diagnosticMitreTacticMap | backend diagnostic fallback | 없음 또는 보강 계산 | status=diagnostic_fallback_by_invariant_category |
| evidence preview | GET /api/scans/{scan_id}/details | evidenceEvents[] | dashboard-db-ingestion-export.json | evidence_events | 100 |
| coverage/charts | GET /api/scans/{scan_id}/details | scanCoverage, scanCoverageMetrics, scanSeverityDistribution, scanZoneViolations, scanTypeViolations | dashboard-db-ingestion-export.json | scan_coverage, scan_severity_distribution, scan_zone_violations, scan_type_violations | coverage=5, severity=2 |
| asset review/history | GET /api/scans/{scan_id}/details | assetEvents, assetHistoryMonthly, assetChanges, assetReviewQueue | asset-changes.jsonl, asset-review-queue.json | asset_events, asset_history_monthly | events=4, reviewQueue=117 |
| LLM/AI1 trace | GET /api/scans/{scan_id}/details, GET /api/scans/{scan_id}/ai1-trace | ai1LlmReviews, ai1EvaluationTraceSummary | ai1-llm-reviews.json, ai1-context-packs.json | 주로 AI Pack latest 보강 | llmReviews=0 |

## 6. 현재 scan/status field와 값
### GET /api/scans/start/status
```json
{
  "running": false,
  "status": "completed",
  "scan_id": "ai-run-20260511-092330",
  "started_at": "2026-05-11T09:23:30Z",
  "finished_at": "2026-05-11T09:23:45Z",
  "elapsed_seconds": 15,
  "duration_seconds": 15,
  "snapshot_size_bytes": 138538773,
  "pid": null,
  "log_path": "/opt/argos/security/ai_runtime/logs/api-start-snapshot-ai-run-20260511-092330.log",
  "catalog_version": "final-20260511-v1",
  "catalog_status": "approved"
}
```
### GET /api/scans 최신 row
```json
{
  "scan_id": "ai-run-20260511-092330",
  "snapshot_id": "asset-snapshot-20260511092343",
  "scanned_at": "2026-05-11T09:23:44.521465+00:00",
  "status": "completed",
  "score": 0,
  "total_violations": 29,
  "critical_high": 15,
  "attack_chains_count": 1,
  "asset_count": 133,
  "service_count": 32,
  "unregistered_count": 117,
  "with_violation_count": 0,
  "online_count": 0,
  "offline_count": 0,
  "snapshot_size_bytes": 138538773
}
```
### GET /api/scans/{scan_id}/details.summary
```json
{
  "total_violations": 29,
  "violated_invariant_count": 29,
  "applied_invariant_count": 27,
  "invariant_total": 56,
  "critical_high": 15,
  "attack_chains": 1
}
```

## 7. detail API top-level field 목록
| field | shape/value | 주요 하위 field |
| --- | --- | --- |
| ai1EvaluationTraceSummary | object | available, count, preview, endpoint, default_payload_policy |
| ai1LlmReviews | array count=0 |  |
| ai2GenerationMetadata | object | mode, provider, model, status, error, context, stage_statuses |
| ai3ReportInput | object | schema_version, run_id, generated_at, status, input_refs, summary, report_sections, ai_report_maker_compatibility |
| aiPackLatest | object | run_id, catalog_version, catalog_status, llm_enabled |
| assetChanges | array count=4 | asset_id, change_id, change_type, current_hash, detected_at, evidence_ids, previous_hash, summary |
| assetEvents | array count=4 | asset_id, asset_name, created_at, description, event_id, event_type, evidence_ids, occurred_at, scan_id, severity, summary, zone |
| assetHistoryMonthly | array count=0 |  |
| assetReviewQueue | array count=117 | candidate_id, evidence_ids, reason, recommended_action, source, suggested_asset_id |
| assets | array count=133 | asset_category, asset_id, asset_name, asset_type, criticality, data_classes, exposure, first_seen, ip, ip_hint, kisa_sheets, last_seen, observation_status, observed_sources, ... (20 cols) |
| attackChains | array count=1 | attack_chain, chain_scenario_id, chain_steps, created_at, current_environment_testable, manual_validation_guide, mitre_attack_flow, related_invariants, risk_level, scenario_basis, source_bundle_id, testability_reason, title |
| coverage | object | 초기침투, 자격증명, 권한상승, 방어우회, 데이터탈취, 내부이동 |
| diagnosticMitreTacticMap | object | schema_version, generated_at, mapping_status, mapping_policy, active_tactic_count, inactive_tactic_count, tactics |
| diagnosticRedteamCandidates | array count=3 | attack_chain, chain_scenario_id, chain_steps, created_at, current_environment_testable, derived, manual_validation_guide, mitre_attack_flow, related_invariants, risk_level, scenario_basis, source_bundle_id, testability_reason, title |
| evidenceEvents | array count=100 | access, actor, actor_role, actor_source_ip_class, asset_id, collected_at, control, event_category, event_type, evidence_id, evidence_type, observed, producer, raw_ref, ... (29 cols) |
| invariantImpact | array count=29 | affected_registry_asset_ids, affected_resource_ids, affected_services, affected_zones, evidence_ids, invariant_id, result_id, severity, status, summary, violation_reason |
| invariants | array count=56 | category, confidence, current_environment_testable, default_zone, description, id, invariant_source, priority, remediation, severity, status, summary, testability_reason, violation_reason, ... (15 cols) |
| mitreMapping | array count=14 | tactic_id, tactic_name, techniques, violated_invariants |
| mitreTacticMap | object | schema_version, generated_at, mapping_policy, active_tactic_count, inactive_tactic_count, tactics, mapping_status |
| pentestResults | array count=0 |  |
| redteamValidation | object | schema_version, generated_at, database_mode, validations, input_contract |
| remediations | array count=56 | attack_phase, description, done, id, invariant_id, priority |
| reportArtifacts | object | schema_version, run_id, generated_at, status, artifacts, future_outputs |
| scanCoverage | array count=5 | metric, scan_id, value |
| scanCoverageMetrics | array count=5 | metric, scan_id, value |
| scanSeverityDistribution | array count=2 | count, scan_id, severity |
| scanTypeViolations | array count=2 | count, invariant_type, scan_id |
| scanZoneViolations | array count=3 | count, scan_id, zone |
| scan_id | ai-run-20260511-092330 | str |
| scanned_at | 2026-05-11T09:23:44.521465+00:00 | str |
| securityPostureTimeline | object | points |
| services | array count=32 | collected_by_wazuh, component_type, deployment_ref, log_source_refs, name, observation_status, owning_asset, owning_asset_id, service_id, vm, zone |
| severityDistribution | array count=4 | color, name, value |
| snapshot_id | asset-snapshot-20260511092343 | str |
| status | completed | str |
| summary | object | total_violations, violated_invariant_count, applied_invariant_count, invariant_total, critical_high, attack_chains |
| typeViolations | array count=3 | color, name, value |
| violations | array count=29 | affected_assets, affected_resources, affected_services, affected_zones, asset_ids, attack_phase, confidence, created_at, current_environment_testable, description, detected_at, evidence_details, evidence_ids, evidence_summaries, ... (37 cols) |
| zoneViolations | array count=1 | count, zone |

## 8. 불변식 catalog: invariants[]
불변식 목록 화면의 원천이다. type/source/category는 화면 분류에 쓰고, title/description은 사람이 읽는 정의로 사용한다.

field 목록:
```text
category
confidence
current_environment_testable
default_zone
description
id
invariant_source
priority
remediation
severity
status
summary
testability_reason
violation_reason
weight
```
현재 sample 값:
```json
{
  "id": "INV-ARG-ACC-01",
  "description": "아르고스 API 요청 시 token·actor의 tenant 정보와 resource의 tenant 정보는 반드시 일치해야 한다",
  "invariant_source": "variable",
  "severity": "High",
  "status": "violated",
  "category": "ACC",
  "default_zone": "",
  "weight": 1,
  "priority": "1개월",
  "remediation": "",
  "confidence": 0.78,
  "violation_reason": "clear_violation",
  "summary": "아르고스 API 요청 시 token·actor의 tenant 정보와 resource의 tenant 정보는 반드시 일치해야 한다 조건과 관련된 위험 evidence가 관측되었다.",
  "current_environment_testable": true,
  "testability_reason": "현재 evidence pack에서 이 불변식의 후보 evidence를 찾고 위험 상태를 점검할 수 있다."
}
```

## 9. 위반 상세: violations[]
보안 담당자가 가장 먼저 봐야 하는 위반 결과다. summary/reason/judgment_summary/evidence_details를 함께 보여줘야 판단 근거가 생긴다.

field 목록:
```text
affected_assets
affected_resources
affected_services
affected_zones
asset_ids
attack_phase
confidence
created_at
current_environment_testable
description
detected_at
evidence_details
evidence_ids
evidence_summaries
first_evidence_at
id
invariant_id
invariant_source
judgment_source
judgment_summary
last_evidence_at
missing_evidence_fields
mitre_tactic
mitre_technique
priority
reason
remediation
result_id
server_zone
severity
status
summary
testability_reason
type
violation_reason
weight
zone
```
현재 sample 값:
```json
{
  "result_id": "ai1-newenv-inv-arg-acc-01-001",
  "invariant_id": "INV-ARG-ACC-01",
  "status": "violated",
  "violation_reason": "clear_violation",
  "summary": "아르고스 API 요청 시 token·actor의 tenant 정보와 resource의 tenant 정보는 반드시 일치해야 한다 조건과 관련된 위험 evidence가 관측되었다.",
  "reason": "token/actor tenant must equal resource tenant before access is allowed.",
  "confidence": 0.78,
  "current_environment_testable": true,
  "testability_reason": "현재 evidence pack에서 이 불변식의 후보 evidence를 찾고 위험 상태를 점검할 수 있다.",
  "created_at": null,
  "asset_ids": [],
  "evidence_ids": [
    "evd-09acf6c9",
    "evd-173b5f6b",
    "evd-3176d3da",
    "evd-31e6202b",
    "evd-41550e3c",
    "evd-50290452",
    "evd-6dfa8623",
    "evd-7a74066b",
    "... 8 more"
  ],
  "severity": "High",
  "description": "아르고스 API 요청 시 token·actor의 tenant 정보와 resource의 tenant 정보는 반드시 일치해야 한다",
  "server_zone": "",
  "zone": "",
  "type": "ACC",
  "attack_phase": "",
  "mitre_tactic": "",
  "mitre_technique": "",
  "weight": 1,
  "invariant_source": "variable",
  "remediation": "",
  "priority": "1개월",
  "evidence_details": [
    {
      "evidence_id": "evd-8065b218",
      "timestamp": "2026-05-11T05:51:45.066048+00:00",
      "evidence_type": "key_management_state",
      "trace_id": "state-scan-20260511054839",
      "request_id": "state-scan-20260511054839",
      "producer_vm": "argos-ops",
      "producer_component_id": "argos-ops-policy-collector",
      "producer_component_type": null,
      "producer_zone": "ops",
      "access_action": null,
      "access_endpoint": null,
      "access_method": null,
      "access_decision": null,
      "access_status_code": null,
      "target_asset_id": null,
      "target_asset_type": null,
      "control_owner_check_performed": null,
      "control_tenant_check_performed": null,
      "control_authz_service_used": null,
      "observed": {
        "scan_id": "ai-run-20260511-092330",
        "summary": "key_management_state | argos-ops",
        "event_type": "key_management_state",
        "source_ref": "/etc/argos/ops/key_registry.json",
        "related_invariant_ids": [
          "INV-ARG-ACC-01",
          "INV-ARG-ACC-02",
          "INV-ARG-ACC-03",
          "INV-ARG-ACC-04",
          "INV-ARG-ACC-05",
          "INV-ARG-ACC-06",
          "INV-ARG-ACC-07",
          "INV-ARG-ACC-08",
          "... 47 more"
        ]
      },
      "raw_ref": {
        "source": "/etc/argos/ops/key_registry.json",
        "agent": null,
        "location": null,
        "log_id": null
      },
      "producer": {
        "vm": "argos-ops",
        "component_id": "argos-ops-policy-collector",
        "component_type": null,
        "zone": "ops"
      },
      "access": {
        "action": null,
        "endpoint": null,
        "method": null,
        "decision": null,
        "status_code": null
      },
      "target": {
        "asset_id": null,
        "asset_type": null
      }
    },
    {
      "evidence_id": "evd-31e6202b",
      "timestamp": "2026-05-11T05:51:45.066400+00:00",
      "evidence_type": "privileged_access_event",
      "trace_id": "state-scan-20260511054839",
      "request_id": "state-scan-20260511054839",
      "producer_vm": "argos-ops",
      "producer_component_id": "argos-ops-policy-collector",
      "producer_component_type": null,
      "producer_zone": "ops",
      "access_action": null,
      "access_endpoint": null,
      "access_method": null,
      "access_decision": null,
      "access_status_code": null,
      "target_asset_id": null,
      "target_asset_type": null,
      "control_owner_check_performed": null,
      "control_tenant_check_performed": null,
      "control_authz_service_used": null,
      "observed": {
        "scan_id": "ai-run-20260511-092330",
        "summary": "privileged_access_event | argos-ops",
        "event_type": "privileged_access_event",
        "source_ref": "/etc/argos/ops/privileged_access_policy.json",
        "related_invariant_ids": [
          "INV-ARG-ACC-01",
          "INV-ARG-ACC-02",
          "INV-ARG-ACC-03",
          "INV-ARG-ACC-04",
          "INV-ARG-ACC-05",
          "INV-ARG-ACC-06",
          "INV-ARG-ACC-07",
          "INV-ARG-ACC-08",
          "... 42 more"
        ]
      },
      "raw_ref": {
        "source": "/etc/argos/ops/privileged_access_policy.json",
        "agent": null,
        "location": null,
        "log_id": null
      },
      "producer": {
        "vm": "argos-ops",
        "component_id": "argos-ops-policy-collector",
        "component_type": null,
        "zone": "ops"
      },
      "access": {
        "action": null,
        "endpoint": null,
        "method": null,
        "decision": null,
        "status_code": null
      },
      "target": {
        "asset_id": null,
        "asset_type": null
      }
    },
    {
      "evidence_id": "evd-173b5f6b",
      "timestamp": "2026-05-11T05:56:45.185823+00:00",
      "evidence_type": "key_management_state",
      "trace_id": "state-scan-20260511055350",
      "request_id": "state-scan-20260511055350",
      "producer_vm": "argos-ops",
      "producer_component_id": "argos-ops-policy-collector",
      "producer_component_type": null,
      "producer_zone": "ops",
      "access_action": null,
      "access_endpoint": null,
      "access_method": null,
      "access_decision": null,
      "access_status_code": null,
      "target_asset_id": null,
      "target_asset_type": null,
      "control_owner_check_performed": null,
      "control_tenant_check_performed": null,
      "control_authz_service_used": null,
      "observed": {
        "scan_id": "ai-run-20260511-092330",
        "summary": "key_management_state | argos-ops",
        "event_type": "key_management_state",
        "source_ref": "/etc/argos/ops/key_registry.json",
        "related_invariant_ids": [
          "INV-ARG-ACC-01",
          "INV-ARG-ACC-02",
          "INV-ARG-ACC-03",
          "INV-ARG-ACC-04",
          "INV-ARG-ACC-05",
          "INV-ARG-ACC-06",
          "INV-ARG-ACC-07",
          "INV-ARG-ACC-08",
          "... 47 more"
        ]
      },
      "raw_ref": {
        "source": "/etc/argos/ops/key_registry.json",
        "agent": null,
        "location": null,
        "log_id": null
      },
      "producer": {
        "vm": "argos-ops",
        "component_id": "argos-ops-policy-collector",
        "component_type": null,
        "zone": "ops"
      },
      "access": {
        "action": null,
        "endpoint": null,
        "method": null,
        "decision": null,
        "status_code": null
      },
      "target": {
        "asset_id": null,
        "asset_type": null
      }
    },
    {
      "evidence_id": "evd-95fbe881",
      "timestamp": "2026-05-11T05:56:45.187063+00:00",
      "evidence_type": "privileged_access_event",
      "trace_id": "state-scan-20260511055350",
      "request_id": "state-scan-20260511055350",
      "producer_vm": "argos-ops",
      "producer_component_id": "argos-ops-policy-collector",
      "produ
...
```

## 10. 자산: assets[]
자산 인벤토리와 영향 범위 표시용이다. status/observation_status, zone, vm, evidence_count, review_status는 필터로 쓰기 좋다.

field 목록:
```text
asset_category
asset_id
asset_name
asset_type
criticality
data_classes
exposure
first_seen
ip
ip_hint
kisa_sheets
last_seen
observation_status
observed_sources
record_hash
related_invariant_ids
segment
type
vm
zone
```
현재 sample 값:
```json
{
  "asset_id": "device-002",
  "asset_name": "argos-ops-api",
  "asset_type": "api",
  "asset_category": "server",
  "observation_status": null,
  "zone": "ops",
  "vm": "argos-ops",
  "ip_hint": null,
  "criticality": "unknown",
  "exposure": "unknown",
  "data_classes": [],
  "observed_sources": [],
  "kisa_sheets": [
    "1. 서버"
  ],
  "first_seen": null,
  "last_seen": null,
  "record_hash": null,
  "related_invariant_ids": [],
  "type": "api",
  "segment": "내부망",
  "ip": null
}
```

## 11. 서비스: services[]
서비스/collector/컴포넌트 목록이다. owning_asset, vm, zone, component_type, observation_status를 자산과 연결한다.

field 목록:
```text
collected_by_wazuh
component_type
deployment_ref
log_source_refs
name
observation_status
owning_asset
owning_asset_id
service_id
vm
zone
```
현재 sample 값:
```json
{
  "service_id": "SVC-ADMIN-001",
  "name": "admin_console_service",
  "owning_asset_id": "APP-ADMIN-001",
  "vm": null,
  "zone": null,
  "component_type": null,
  "deployment_ref": "deploy://unknown/services/svc-admin-001",
  "log_source_refs": [],
  "collected_by_wazuh": null,
  "observation_status": "expected",
  "owning_asset": "operator_admin_console"
}
```

## 12. evidence preview: evidenceEvents[]
원문 evidence 전체가 아니라 프론트 표시용 preview다. 위반 상세에서는 violations[].evidence_details를 우선 사용한다.

field 목록:
```text
access
actor
actor_role
actor_source_ip_class
asset_id
collected_at
control
event_category
event_type
evidence_id
evidence_type
observed
producer
raw_ref
request_id
schema_version
summary
target
timestamp
token
token_issued_by_auth_server
token_jti
token_kid
token_revoked
token_signature_valid
token_sub
token_tenant
trace_id
type
```
현재 sample 값:
```json
{
  "evidence_id": "evd-7dd1cdf5",
  "timestamp": "2026-05-11T06:31:46.021621+00:00",
  "schema_version": null,
  "trace_id": "state-scan-20260511063037",
  "request_id": "state-scan-20260511063037",
  "event_category": "environment_state",
  "evidence_type": "key_management_state",
  "actor_role": null,
  "actor_source_ip_class": null,
  "token_sub": null,
  "token_tenant": null,
  "token_kid": null,
  "token_jti": null,
  "token_signature_valid": null,
  "token_issued_by_auth_server": null,
  "token_revoked": null,
  "observed": {
    "scan_id": "ai-run-20260511-092330",
    "summary": "key_management_state | argos-ops",
    "event_type": "key_management_state",
    "source_ref": "/etc/argos/ops/key_registry.json",
    "related_invariant_ids": [
      "INV-ARG-CRED-01"
    ]
  },
  "producer": {
    "vm": "argos-ops",
    "component_id": "argos-ops-policy-collector",
    "component_type": null,
    "zone": "ops",
    "asset_id": null,
    "service_id": null
  },
  "actor": null,
  "token": null,
  "access": {
    "action": null,
    "endpoint": null,
    "method": null,
    "decision": null,
    "status_code": null
  },
  "target": {
    "asset_id": null,
    "asset_type": null,
    "owner_id": null,
    "tenant_id": null
  },
  "control": {
    "owner_check_performed": null,
    "tenant_check_performed": null,
    "authz_service_used": null
  },
  "raw_ref": {
    "source": "/etc/argos/ops/key_registry.json",
    "agent": null,
    "location": null,
    "log_id": null
  },
  "event_type": "key_management_state",
  "type": "key_management_state",
  "summary": "key_management_state | argos-ops",
  "asset_id": null,
  "collected_at": "2026-05-11T06:31:46.021621+00:00"
}
```

## 13. 공식 공격 체인: attackChains[]
AI2가 공식으로 만든 체인이다. Red Team 공식 시나리오 후보로 쓸 수 있는 것은 이 배열이다.

field 목록:
```text
attack_chain
chain_scenario_id
chain_steps
created_at
current_environment_testable
manual_validation_guide
mitre_attack_flow
related_invariants
risk_level
scenario_basis
source_bundle_id
testability_reason
title
```
현재 sample 값:
```json
{
  "chain_scenario_id": "chain-bundle-pack-scenario-1-001-ai1-violated-candidate-primary-evidence-correlation",
  "created_at": null,
  "title": "Evidence 기반 체인 후보: 보안 통제",
  "source_bundle_id": null,
  "risk_level": "high",
  "scenario_basis": {
    "status": null,
    "violation_reason": null,
    "summary": null
  },
  "current_environment_testable": true,
  "testability_reason": "AI1 diagnostic bundle의 trace 20개, actor 2개, cluster 1개를 evidence correlation 기준으로 연결했다.",
  "attack_chain": [
    "chain-bundle-pack-scenario-1-001-ai1-violated-candidate-primary-evidence-correlation-step-01"
  ],
  "chain_steps": [
    {
      "order": 1,
      "path": null,
      "location": null,
      "violation_point": "chain-bundle-pack-scenario-1-001-ai1-violated-candidate-primary-evidence-correlation-step-01",
      "related_invariants": [],
      "evidence_ids": [
        "evd-05d20379",
        "evd-09acf6c9",
        "evd-0ed52fd6",
        "evd-0f62628f",
        "evd-1180ea81",
        "evd-11f0c726",
        "evd-173b5f6b",
        "evd-19a466e8",
        "... 46 more"
      ],
      "transition_to_next": null,
      "threatened_asset_ids": []
    }
  ],
  "related_invariants": [
    "INV-ARG-ACC-01",
    "INV-ARG-ACC-02",
    "INV-ARG-ACC-03",
    "INV-ARG-ACC-04",
    "INV-ARG-ACC-05",
    "INV-ARG-ACC-06",
    "INV-ARG-ACC-07",
    "INV-ARG-ACC-08",
    "... 21 more"
  ],
  "mitre_attack_flow": [],
  "manual_validation_guide": null
}
```

## 14. 진단용 체인 후보: diagnosticRedteamCandidates[]
공식 AI2 체인이 부족할 때 백엔드가 보여주는 진단용 후보다. 공식 시나리오로 저장하거나 Red Team 결과와 섞으면 안 된다.

field 목록:
```text
attack_chain
chain_scenario_id
chain_steps
created_at
current_environment_testable
derived
manual_validation_guide
mitre_attack_flow
related_invariants
risk_level
scenario_basis
source_bundle_id
testability_reason
title
```
현재 sample 값:
```json
{
  "chain_scenario_id": "redteam-derived-credential-to-identity-to-audit",
  "created_at": "2026-05-11T09:35:23.024326+00:00",
  "title": "인증정보 노출에서 권한 오용과 탐지 회피까지의 검증 체인",
  "source_bundle_id": "derived-from-ai1-violations-and-final-invariant-catalog",
  "risk_level": "high",
  "scenario_basis": {
    "status": "violated",
    "violation_reason": "derived_redteam_candidate",
    "summary": "AI2 원본이 하나의 evidence cluster만 반환했기 때문에, 최종 불변식 카테고리와 MITRE fallback 전술을 기준으로 레드팀 검증 후보 체인을 생성했다."
  },
  "current_environment_testable": true,
  "testability_reason": "CRED, ACC, AUD 카테고리의 위반 evidence가 존재한다. 단, 실제 공격 성공 시나리오 확정이 아니라 승인된 검증 절차를 위한 후보 체인이다.",
  "attack_chain": [
    "redteam-derived-credential-to-identity-to-audit-step-01",
    "redteam-derived-credential-to-identity-to-audit-step-02",
    "redteam-derived-credential-to-identity-to-audit-step-03"
  ],
  "chain_steps": [
    {
      "order": 1,
      "path": "인증정보 통제",
      "location": "인증정보 통제",
      "violation_point": "인증정보 통제 영역의 위반 불변식 5개를 기준으로 승인된 테스트 계정/자산에서 재현 가능한지 검증한다. 대표 근거: 펌웨어 서명키는 argos-signing 또는 승인된 KMS/HSM에서만 사용되어야 하며 argos-ops·argos-dmz·Git·CI 로그·개발자 PC에 노출되면 안 된다 조건과 관련된 위험 evidence가 관측되었다.",
      "step": "인증정보 통제 영역의 위반 불변식 5개를 기준으로 승인된 테스트 계정/자산에서 재현 가능한지 검증한다. 대표 근거: 펌웨어 서명키는 argos-signing 또는 승인된 KMS/HSM에서만 사용되어야 하며 argos-ops·argos-dmz·Git·CI 로그·개발자 PC에 노출되면 안 된다 조건과 관련된 위험 evidence가 관측되었다.",
      "reason": "최종 불변식 카테고리와 MITRE fallback 전술을 기준으로 AI2 단일 cluster를 레드팀 검증 경로로 분해했다.",
      "tactic": "TA0006",
      "tactic_name": "Credential Access",
      "technique": "",
      "related_invariants": [
        "INV-ARG-CRED-01",
        "INV-ARG-CRED-02",
        "INV-ARG-CRED-03",
        "INV-STD-CRED-01",
        "INV-STD-CRED-02"
      ],
      "evidence_ids": [
        "evd-173b5f6b",
        "evd-3176d3da",
        "evd-41550e3c",
        "evd-7a74066b",
        "evd-7dd1cdf5",
        "evd-8065b218",
        "evd-aa4b7825",
        "evd-b8421f43",
        "... 1 more"
      ],
      "evidence_count": 9,
      "evidence_preview_limit": 25,
      "threatened_asset_ids": [],
      "threatened_asset_count": 0
    },
    {
      "order": 2,
      "path": "계정/권한 통제",
      "location": "계정/권한 통제",
      "violation_point": "계정/권한 통제 영역의 위반 불변식 10개를 기준으로 승인된 테스트 계정/자산에서 재현 가능한지 검증한다. 대표 근거: 아르고스 API 요청 시 token·actor의 tenant 정보와 resource의 tenant 정보는 반드시 일치해야 한다 조건과 관련된 위험 evidence가 관측되었다.",
      "step": "계정/권한 통제 영역의 위반 불변식 10개를 기준으로 승인된 테스트 계정/자산에서 재현 가능한지 검증한다. 대표 근거: 아르고스 API 요청 시 token·actor의 tenant 정보와 resource의 tenant 정보는 반드시 일치해야 한다 조건과 관련된 위험 evidence가 관측되었다.",
      "reason": "최종 불변식 카테고리와 MITRE fallback 전술을 기준으로 AI2 단일 cluster를 레드팀 검증 경로로 분해했다.",
      "tactic": "TA0004",
      "tactic_name": "Privilege Escalation",
      "technique": "",
      "related_invariants": [
        "INV-ARG-ACC-01",
        "INV-ARG-ACC-02",
        "INV-ARG-ACC-03",
        "INV-ARG-ACC-04",
        "INV-ARG-ACC-05",
        "INV-ARG-ACC-06",
        "INV-ARG-ACC-07",
        "INV-ARG-ACC-08",
        "... 2 more"
      ],
      "evidence_ids": [
        "evd-09acf6c9",
        "evd-173b5f6b",
        "evd-3176d3da",
        "evd-31e6202b",
        "evd-41550e3c",
        "evd-50290452",
        "evd-6dfa8623",
        "evd-7a74066b",
        "... 8 more"
      ],
      "evidence_count": 16,
      "evidence_preview_limit": 25,
      "threatened_asset_ids": [],
      "threatened_asset_count": 0
    },
    {
      "order": 3,
      "path": "감사/탐지 통제",
      "location": "감사/탐지 통제",
      "violation_point": "감사/탐지 통제 영역의 위반 불변식 14개를 기준으로 승인된 테스트 계정/자산에서 재현 가능한지 검증한다. 대표 근거: 동일 주체가 다수 owner/tenant/device를 반복 조회하는 행위는 이상행위로 탐지 및 로깅한다 조건과 관련된 위험 evidence가 관측되었다.",
      "step": "감사/탐지 통제 영역의 위반 불변식 14개를 기준으로 승인된 테스트 계정/자산에서 재현 가능한지 검증한다. 대표 근거: 동일 주체가 다수 owner/tenant/device를 반복 조회하는 행위는 이상행위로 탐지 및 로깅한다 조건과 관련된 위험 evidence가 관측되었다.",
      "reason": "최종 불변식 카테고리와 MITRE fallback 전술을 기준으로 AI2 단일 cluster를 레드팀 검증 경로로 분해했다.",
      "tactic": "TA0005",
      "tactic_name": "Defense Evasion",
      "technique": "",
      "related_invariants": [
        "INV-ARG-AUD-01",
        "INV-ARG-AUD-02",
        "INV-ARG-AUD-03",
        "INV-ARG-AUD-04",
        "INV-ARG-AUD-05",
        "INV-ARG-AUD-06",
        "INV-ARG-AUD-07",
        "INV-ARG-AUD-08",
        "... 6 more"
      ],
      "evidence_ids": [
        "evd-038f72f6",
        "evd-05d20379",
        "evd-070169e5",
        "evd-0ed52fd6",
        "evd-11f0c726",
        "evd-173b5f6b",
        "evd-192a0da7",
        "evd-192c4f39",
        "... 17 more"
      ],
      "evidence_count": 114,
      "evidence_preview_limit": 25,
      "threatened_asset_ids": [],
      "threatened_asset_count": 0
    }
  ],
  "related_invariants": [
    "INV-ARG-CRED-01",
    "INV-ARG-CRED-02",
    "INV-ARG-CRED-03",
    "INV-STD-CRED-01",
    "INV-STD-CRED-02",
    "INV-ARG-ACC-01",
    "INV-ARG-ACC-02",
    "INV-ARG-ACC-03",
    "... 21 more"
  ],
  "mitre_attack_flow": [
    {
      "order": 1,
      "tactic": "TA0006",
      "tactic_name": "Credential Access",
      "technique": "",
      "step": "인증정보 통제 영역의 위반 불변식 5개를 기준으로 승인된 테스트 계정/자산에서 재현 가능한지 검증한다. 대표 근거: 펌웨어 서명키는 argos-signing 또는 승인된 KMS/HSM에서만 사용되어야 하며 argos-ops·argos-dmz·Git·CI 로그·개발자 PC에 노출되면 안 된다 조건과 관련된 위험 evidence가 관측되었다.",
      "reason": "MITRE는 체인 정렬의 보조 전술 라벨이며, 실제 검증 기준은 related_invariants와 evidence_ids다.",
      "related_invariants": [
        "INV-ARG-CRED-01",
        "INV-ARG-CRED-02",
        "INV-ARG-CRED-03",
        "INV-STD-CRED-01",
        "INV-STD-CRED-02"
      ]
    },
    {
      "order": 2,
      "tactic": "TA0004",
      "tactic_name": "Privilege Escalation",
      "technique": "",
      "step": "계정/권한 통제 영역의 위반 불변식 10개를 기준으로 승인된 테스트 계정/자산에서 재현 가능한지 검증한다. 대표 근거: 아르고스 API 요청 시 token·actor의 tenant 정보와 resource의 tenant 정보는 반드시 일치해야 한다 조건과 관련된 위험 evidence가 관측되었다.",
      "reason": "MITRE는 체인 정렬의 보조 전술 라벨이며, 실제 검증 기준은 related_invariants와 evidence_ids다.",
      "related_invariants": [
        "INV-ARG-ACC-01",
        "INV-ARG-ACC-02",
        "INV-ARG-ACC-03",
        "INV-ARG-ACC-04",
        "INV-ARG-ACC-05",
        "INV-ARG-ACC-06",
        "INV-ARG-ACC-07",
        "INV-ARG-ACC-08",
        "... 2 more"
      ]
    },
    {
      "order": 3,
      "tactic": "TA0005",
      "tactic_name": "Defense Evasion",
      "technique": "",
      "step": "감사/탐지 통제 영역의 위반 불변식 14개를 기준으로 승인된 테스트 계정/자산에서 재현 가능한지 검증한다. 대표 근거: 동일 주체가 다수 owner/tenant/device를 반복 조회하는 행위는 이상행위로 탐지 및 로깅한다 조건과 관련된 위험 evidence가 관측되었다.",
      "reason": "MITRE는 체인 정렬의 보조 전술 라벨이며, 실제 검증 기준은 related_invariants와 evidence_ids다.",
      "related_invariants": [
        "INV-ARG-AUD-01",
        "INV-ARG-AUD-02",
        "INV-ARG-AUD-03",
        "INV-ARG-AUD-04",
        "INV-ARG-AUD-05",
        "INV-ARG-AUD-06",
        "INV-ARG-AUD-07",
        "INV-ARG-AUD-08",
        "... 6 more"
      ]
    }
  ],
  "manual_validation_guide": {
    "goal": "위반 불변식 간 연결이 실제 승인 검증 환경에서 재현 가능한지 확인한다.",
    "steps": [
      "각 단계의 related_invariants와 evidence_i
...
```

## 15. 공식 MITRE: mitreTacticMap
현재 공식 MITRE는 evidence 부족으로 미매핑 상태다. tactics active가 0이면 미매핑으로 표시한다.
현재 sample 값:
```json
{
  "schema_version": "argos-dashboard-mitre-tactic-map",
  "generated_at": "2026-05-11T09:23:44.218550+00:00",
  "mapping_policy": {
    "mitre_scope": "enterprise_tactic_only",
    "mitre_is_chain_generation_source": false,
    "chain_generation_basis": [
      "ai1_violated_results",
      "evidence_correlation",
      "asset_registry",
      "invariant_relationship"
    ],
    "ui_policy": "show_active_tactics_by_default"
  },
  "active_tactic_count": 0,
  "inactive_tactic_count": 14,
  "tactics": [
    {
      "tactic_id": "TA0043",
      "tactic_name": "Reconnaissance",
      "active": false,
      "violation_count": 0,
      "invariants": []
    },
    {
      "tactic_id": "TA0042",
      "tactic_name": "Resource Development",
      "active": false,
      "violation_count": 0,
      "invariants": []
    },
    {
      "tactic_id": "TA0001",
      "tactic_name": "Initial Access",
      "active": false,
      "violation_count": 0,
      "invariants": []
    },
    {
      "tactic_id": "TA0002",
      "tactic_name": "Execution",
      "active": false,
      "violation_count": 0,
      "invariants": []
    },
    {
      "tactic_id": "TA0003",
      "tactic_name": "Persistence",
      "active": false,
      "violation_count": 0,
      "invariants": []
    },
    {
      "tactic_id": "TA0004",
      "tactic_name": "Privilege Escalation",
      "active": false,
      "violation_count": 0,
      "invariants": []
    },
    {
      "tactic_id": "TA0005",
      "tactic_name": "Defense Evasion",
      "active": false,
      "violation_count": 0,
      "invariants": []
    },
    {
      "tactic_id": "TA0006",
      "tactic_name": "Credential Access",
      "active": false,
      "violation_count": 0,
      "invariants": []
    },
    "... 6 more"
  ],
  "mapping_status": "missing_or_insufficient_evidence"
}
```

## 16. 진단용 MITRE: diagnosticMitreTacticMap
불변식 category 기반 보조 매핑이다. 화면에서는 “진단용” 또는 “추정”으로 표시해야 한다.
현재 sample 값:
```json
{
  "schema_version": "argos-dashboard-mitre-tactic-map",
  "generated_at": "2026-05-11T09:35:23.077003+00:00",
  "mapping_status": "diagnostic_fallback_by_invariant_category",
  "mapping_policy": {
    "mitre_scope": "enterprise_tactic_only",
    "mitre_is_chain_generation_source": false,
    "ui_policy": "diagnostic_only_not_official_ai_pack_mapping"
  },
  "active_tactic_count": 3,
  "inactive_tactic_count": 11,
  "tactics": [
    {
      "tactic_id": "TA0043",
      "tactic_name": "Reconnaissance",
      "active": false,
      "violation_count": 0,
      "violated_invariants": [],
      "invariants": [],
      "mapping_basis": "fallback_by_invariant_category"
    },
    {
      "tactic_id": "TA0042",
      "tactic_name": "Resource Development",
      "active": false,
      "violation_count": 0,
      "violated_invariants": [],
      "invariants": [],
      "mapping_basis": "fallback_by_invariant_category"
    },
    {
      "tactic_id": "TA0001",
      "tactic_name": "Initial Access",
      "active": false,
      "violation_count": 0,
      "violated_invariants": [],
      "invariants": [],
      "mapping_basis": "fallback_by_invariant_category"
    },
    {
      "tactic_id": "TA0002",
      "tactic_name": "Execution",
      "active": false,
      "violation_count": 0,
      "violated_invariants": [],
      "invariants": [],
      "mapping_basis": "fallback_by_invariant_category"
    },
    {
      "tactic_id": "TA0003",
      "tactic_name": "Persistence",
      "active": false,
      "violation_count": 0,
      "violated_invariants": [],
      "invariants": [],
      "mapping_basis": "fallback_by_invariant_category"
    },
    {
      "tactic_id": "TA0004",
      "tactic_name": "Privilege Escalation",
      "active": true,
      "violation_count": 10,
      "violated_invariants": [
        "INV-ARG-ACC-01",
        "INV-ARG-ACC-02",
        "INV-ARG-ACC-03",
        "INV-ARG-ACC-04",
        "INV-ARG-ACC-05",
        "INV-ARG-ACC-06",
        "INV-ARG-ACC-07",
        "INV-ARG-ACC-08",
        "... 2 more"
      ],
      "invariants": [
        "INV-ARG-ACC-01",
        "INV-ARG-ACC-02",
        "INV-ARG-ACC-03",
        "INV-ARG-ACC-04",
        "INV-ARG-ACC-05",
        "INV-ARG-ACC-06",
        "INV-ARG-ACC-07",
        "INV-ARG-ACC-08",
        "... 2 more"
      ],
      "mapping_basis": "fallback_by_invariant_category"
    },
    {
      "tactic_id": "TA0005",
      "tactic_name": "Defense Evasion",
      "active": true,
      "violation_count": 14,
      "violated_invariants": [
        "INV-ARG-AUD-01",
        "INV-ARG-AUD-02",
        "INV-ARG-AUD-03",
        "INV-ARG-AUD-04",
        "INV-ARG-AUD-05",
        "INV-ARG-AUD-06",
        "INV-ARG-AUD-07",
        "INV-ARG-AUD-08",
        "... 6 more"
      ],
      "invariants": [
        "INV-ARG-AUD-01",
        "INV-ARG-AUD-02",
        "INV-ARG-AUD-03",
        "INV-ARG-AUD-04",
        "INV-ARG-AUD-05",
        "INV-ARG-AUD-06",
        "INV-ARG-AUD-07",
        "INV-ARG-AUD-08",
        "... 6 more"
      ],
      "mapping_basis": "fallback_by_invariant_category"
    },
    {
      "tactic_id": "TA0006",
      "tactic_name": "Credential Access",
      "active": true,
      "violation_count": 5,
      "violated_invariants": [
        "INV-ARG-CRED-01",
        "INV-ARG-CRED-02",
        "INV-ARG-CRED-03",
        "INV-STD-CRED-01",
        "INV-STD-CRED-02"
      ],
      "invariants": [
        "INV-ARG-CRED-01",
        "INV-ARG-CRED-02",
        "INV-ARG-CRED-03",
        "INV-STD-CRED-01",
        "INV-STD-CRED-02"
      ],
      "mapping_basis": "fallback_by_invariant_category"
    },
    "... 6 more"
  ]
}
```

## 17. chart/운영 보조 데이터
| field | count/value | sample |
| --- | --- | --- |
| severityDistribution | 4 | {"name": "Critical", "value": 0, "color": "#0C447C"} |
| zoneViolations | 1 | {"zone": "", "count": 29} |
| typeViolations | 3 | {"name": "AUD", "value": 14, "color": "#0C447C"} |
| scanSeverityDistribution | 2 | {"scan_id": "ai-run-20260511-092330", "severity": "high", "count": 15} |
| scanZoneViolations | 3 | {"scan_id": "ai-run-20260511-092330", "zone": "dmz", "count": 13} |
| scanTypeViolations | 2 | {"scan_id": "ai-run-20260511-092330", "invariant_type": "ARG", "count": 21} |
| scanCoverage | 5 | {"scan_id": "ai-run-20260511-092330", "metric": "asset_count", "value": 133} |
| scanCoverageMetrics | 5 | {"scan_id": "ai-run-20260511-092330", "metric": "asset_count", "value": 133} |
| assetEvents | 4 | {"event_id": "asset-change-updated-asset-snapshot-20260511092343-OBS-ARGOS-DMZ-ARGOS-DMZ-NGINX", "scan_id": "ai-run-20260511-092330", "event_type": "asset_updated", "asset_id": "OBS-ARGOS-DMZ-ARGOS-DMZ-NGINX", "asset_nam... |
| assetHistoryMonthly | 0 |  |
| assetChanges | 4 | {"change_id": "asset-change-updated-asset-snapshot-20260511092343-OBS-ARGOS-DMZ-ARGOS-DMZ-NGINX", "detected_at": "2026-05-11T09:23:43.767153Z", "change_type": "asset_updated", "asset_id": "OBS-ARGOS-DMZ-ARGOS-DMZ-NGINX",... |
| assetReviewQueue | 117 | {"candidate_id": "asset-candidate-DISC-SVC-ARGOS-DATA-ARGOS-DATA-STORAGE-COLLECTOR", "suggested_asset_id": "DISC-SVC-ARGOS-DATA-ARGOS-DATA-STORAGE-COLLECTOR", "reason": "evidence에서 신규 service/component/resource가 관측됐지만 ap... |
| invariantImpact | 29 | {"invariant_id": "INV-ARG-ACC-01", "result_id": "ai1-newenv-inv-arg-acc-01-001", "status": "violated", "violation_reason": "clear_violation", "severity": "high", "evidence_ids": ["evd-09acf6c9", "evd-173b5f6b", "evd-3176... |
| remediations | 56 | {"id": 1177, "invariant_id": "INV-ARG-ACC-01", "description": "관련 서비스의 정책/인가/탐지 설정을 보강하고 Red Team 재검증을 수행한다.", "attack_phase": null, "priority": "즉시", "done": false} |
| pentestResults | 0 |  |
| ai1LlmReviews | 0 |  |
| ai1EvaluationTraceSummary | {"available": true, "count": 56, "preview": [{"context_pack_id": "ctx-ai1-inv-arg-acc-01-001", "target_ai": "ai1-invariant-evaluator", "invariant_id": "INV-ARG-ACC-01", "evidence_count": 0}, {"context_pack_id": "ctx-ai1-... | {"available": true, "count": 56, "preview": [{"context_pack_id": "ctx-ai1-inv-arg-acc-01-001", "target_ai": "ai1-invariant-evaluator", "invariant_id": "INV-ARG-ACC-01", "evidence_count": 0}, {"context_pack_id": "ctx-ai1-... |

## 18. AI Pack latest 파일별 역할
| file | server path | size | role | API field |
| --- | --- | --- | --- | --- |
| ai1-context-packs.json | /opt/argos/security/ai_runtime/dashboard_api/latest/ai1-context-packs.json | 2,063,508 | AI1 판단 context/evidence bundle | violations[] |
| ai1-llm-reviews.json | /opt/argos/security/ai_runtime/dashboard_api/latest/ai1-llm-reviews.json | 3 | LLM review 결과. 현재 0건일 수 있음 | violations[] |
| ai2-chain-scenarios.json | /opt/argos/security/ai_runtime/dashboard_api/latest/ai2-chain-scenarios.json | 49,314 | 공식 AI2 공격 체인 | summary.total_violations, violated_invariant_count, applied_invariant_count, invariant_total, critical_high, attack_chains |
| ai2-generation-metadata.json | /opt/argos/security/ai_runtime/dashboard_api/latest/ai2-generation-metadata.json | 41,995 | AI2 생성 메타데이터 | 보조/향후 |
| ai3-report-input.json | /opt/argos/security/ai_runtime/dashboard_api/latest/ai3-report-input.json | 1,954 | 향후 보고서 생성 입력 | 보조/향후 |
| ai3-report-maker-db-export.json | /opt/argos/security/ai_runtime/dashboard_api/latest/ai3-report-maker-db-export.json | 43,497 | 향후 보고서 DB export | 보조/향후 |
| asset-changes.jsonl | /opt/argos/security/ai_runtime/dashboard_api/latest/asset-changes.jsonl | 75,173 | 자산 변경 이벤트 | assetEvents, assetHistoryMonthly, assetChanges, assetReviewQueue |
| asset-invariant-impact.json | /opt/argos/security/ai_runtime/dashboard_api/latest/asset-invariant-impact.json | 34,556 | 자산-불변식 영향 관계 | assets[], services[] |
| asset-review-queue.json | /opt/argos/security/ai_runtime/dashboard_api/latest/asset-review-queue.json | 170,908 | 검토 필요 자산 queue | assetEvents, assetHistoryMonthly, assetChanges, assetReviewQueue |
| assets.json | /opt/argos/security/ai_runtime/dashboard_api/latest/assets.json | 261,501 | 자산 inventory | assets[], services[] |
| custom-invariants.json | /opt/argos/security/ai_runtime/dashboard_api/latest/custom-invariants.json | 35,915 | 가변/custom 불변식 catalog | invariants[] |
| dashboard-db-ingestion-export.json | /opt/argos/security/ai_runtime/dashboard_api/latest/dashboard-db-ingestion-export.json | 634,315 | PostgreSQL ingest 계약 파일 | scan_id, scanned_at, status, asset_count, service_count, total_violations, attack_chains_count, snapshot_size_bytes, elapsed_seconds |
| disabled-invariants.json | /opt/argos/security/ai_runtime/dashboard_api/latest/disabled-invariants.json | 195 | 비활성 불변식 | invariants[] |
| fixed-invariants.json | /opt/argos/security/ai_runtime/dashboard_api/latest/fixed-invariants.json | 15,471 | 고정 불변식 catalog | invariants[] |
| invariant-catalog.json | /opt/argos/security/ai_runtime/dashboard_api/latest/invariant-catalog.json | 51,192 | AI Pack latest 산출물 | invariants[] |
| invariant-results.json | /opt/argos/security/ai_runtime/dashboard_api/latest/invariant-results.json | 87,694 | AI1 불변식 적용/위반 결과 | summary.total_violations, violated_invariant_count, applied_invariant_count, invariant_total, critical_high, attack_chains |
| kisa-asset-inventory.json | /opt/argos/security/ai_runtime/dashboard_api/latest/kisa-asset-inventory.json | 62,162 | AI Pack latest 산출물 | assets[], services[] |
| mitre-tactic-map.json | /opt/argos/security/ai_runtime/dashboard_api/latest/mitre-tactic-map.json | 2,680 | 공식 MITRE mapping 원천 | mitreTacticMap, mitreMapping |
| redteam-validation.json | /opt/argos/security/ai_runtime/dashboard_api/latest/redteam-validation.json | 607 | 레드팀 검증 입력/결과 | 보조/향후 |
| report-artifacts.json | /opt/argos/security/ai_runtime/dashboard_api/latest/report-artifacts.json | 296 | 보고서 산출물 메타 | 보조/향후 |
| scan-detail.json | /opt/argos/security/ai_runtime/dashboard_api/latest/scan-detail.json | 3,533 | API detail 보강 파일 | 보조/향후 |
| security-posture-point.json | /opt/argos/security/ai_runtime/dashboard_api/latest/security-posture-point.json | 160,093 | AI Pack latest 산출물 | 보조/향후 |
| security-posture-timeline.json | /opt/argos/security/ai_runtime/dashboard_api/latest/security-posture-timeline.json | 4,304,192 | 보안 추이 | 보조/향후 |
| summary.json | /opt/argos/security/ai_runtime/dashboard_api/latest/summary.json | 2,776 | scan summary/KPI 원천 | scan_id, scanned_at, status, asset_count, service_count, total_violations, attack_chains_count, snapshot_size_bytes, elapsed_seconds |

## 19. dashboard-db-ingestion-export table 계약
이 파일은 AI Pack 결과를 PostgreSQL에 넣는 계약이다. 프론트가 직접 읽지는 않지만 API field가 어떤 DB table에서 오는지 확인할 때 참고한다.
| AI export table | rows | columns | DB table | API usage |
| --- | --- | --- | --- | --- |
| asset_events | 4 | asset_id, created_at, event_id, event_type, evidence_ids, scan_id, summary | asset_events | details.assetEvents |
| asset_history_monthly | 1 | asset_count, company_id, month, observed_asset_count, review_required_count, violated_invariant_count | asset_history_monthly | details.assetHistoryMonthly |
| asset_related_invariants | 56 | asset_id, invariant_id | asset_related_invariants | details.assets/invariantImpact |
| asset_services | 40 | asset_id, service_id | asset_services | details.services/assets relation |
| assets | 133 | asset_category, asset_id, asset_name, asset_type, company_id, criticality, data_classes, evidence_count, exposure, first_observed_at, ip_hint, kisa_sheets, last_observed_at, owner_team, review_status, status, ... (18 cols) | assets | details.assets |
| attack_chain_invariants | 29 | chain_scenario_id, invariant_id | attack_chain_invariants | attackChains[].invariants |
| attack_chain_steps | 1 | affected_asset_ids, category, chain_scenario_id, endpoint, evidence_ids, finding, redteam_focus, step_id, step_order, title, vm, zone | attack_chain_steps | attackChains[].steps |
| attack_chains | 1 | chain_scenario_id, current_environment_testable, risk_level, scan_id, scenario_basis, testability_reason, threatened_asset_count, title | attack_chains | details.attackChains |
| evidence_events | 65 | event_type, evidence_id, producer_component_id, producer_vm, producer_zone, related_invariant_ids, request_id, scan_id, source_event_id, source_ref, summary, timestamp, trace_id | evidence_events | details.evidenceEvents, violations[].evidence_details |
| invariant_impact | 29 | affected_asset_count, affected_service_count, invariant_id, result_id, scan_id, severity, status, summary, violation_reason | invariant_impact | details.invariantImpact |
| invariant_impact_evidence | 551 | evidence_id, invariant_id, scan_id | invariant_impact_evidence | invariantImpact/evidence relation |
| invariant_impact_registry_assets | 56 | asset_id, invariant_id, scan_id | invariant_impact_registry_assets | invariantImpact/assets relation |
| invariant_impact_services | 0 |  | invariant_impact_services | invariantImpact/services relation |
| invariants | 56 | active, catalog_status, category, invariant_id, last_result_status, last_violation_reason, required_evidence, severity, source, title, verification_logic | invariants | details.invariants |
| mitre_attack_flow | 14 | active, mapping_scope, scan_id, tactic_id, tactic_name, violation_count | mitre_attack_flow | details.mitreTacticMap/mitreMapping |
| mitre_flow_invariants | 0 |  | mitre_flow_invariants | details.mitreMapping |
| pentest_related_invariants | 0 |  | pentest_related_invariants | pentest relations |
| pentest_results | 0 |  | pentest_results | details.pentestResults |
| pentest_target_assets | 0 |  | pentest_target_assets | pentest relations |
| remediations | 56 | asset_id, invariant_id, priority, recommended_action, scan_id, status | remediations | details.remediations |
| scan_asset_snapshot | 133 | asset_id, criticality, evidence_count, scan_id, status, vm, zone | scan_asset_snapshot | /api/scans asset counters |
| scan_coverage | 5 | metric, scan_id, value | scan_coverage | details.scanCoverage, scanCoverageMetrics |
| scan_severity_distribution | 2 | count, scan_id, severity | scan_severity_distribution | details.scanSeverityDistribution |
| scan_type_violations | 2 | count, invariant_type, scan_id | scan_type_violations | details.scanTypeViolations |
| scan_zone_violations | 3 | count, scan_id, zone | scan_zone_violations | details.scanZoneViolations |
| scans | 1 | asset_count, attack_chains_count, company_id, evidence_count, invariant_result_count, llm_enabled, scan_id, scanned_at, service_count, snapshot_id, source_rows_read, status, violated_invariant_count | scans | /api/scans, details.summary |
| services | 32 | collected_by_wazuh, company_id, component_type, deployment_ref, log_source_refs, observation_status, owning_asset, service_id, service_name, vm, zone | services | details.services |
| violation_assets | 0 |  | violation_assets | violations[].affected_assets |
| violation_evidence | 551 | evidence_id, invariant_id, scan_id | violation_evidence | violations[].evidence_details |
| violations | 29 | confidence, current_environment_testable, invariant_id, reason, result_id, scan_id, severity, status, summary, testability_reason, violation_reason | violations | details.violations |

## 20. PostgreSQL 주요 table/column
| table | columns |
| --- | --- |
| scans | scan_id, snapshot_id, scanned_at, status, score, total_violations, critical_high, attack_chains_count, asset_count, service_count |
| invariants | invariant_id, description, invariant_source, severity, default_zone, category, weight, attack_phase, remediation_default |
| violations | result_id, scan_id, invariant_id, status, violation_reason, summary, reason, confidence, current_environment_testable, testability_reason, created_at |
| violation_evidence | violation_id, evidence_id |
| violation_assets | violation_id, asset_id |
| evidence_events | evidence_id, timestamp, schema_version, trace_id, request_id, event_category, evidence_type, producer_vm, producer_component_id, producer_component_type, producer_zone, producer_asset_id, producer_service_id, actor_id, actor_role, actor_source_ip_class, token_present, token_sub, token_tenant, token_kid, token_jti, token_signature_valid, token_issued_by_auth_server, token_revoked, access_action, access_endpoint, access_method, access_decision, ... (41 cols) |
| assets | asset_id, asset_name, asset_type, asset_category, observation_status, zone, vm, ip_hint, criticality, exposure, data_classes, observed_sources, kisa_sheets, first_seen, last_seen, record_hash, company_id, snapshot_id, evidence_refs |
| services | service_id, name, owning_asset_id, vm, zone, component_type, deployment_ref, log_source_refs, collected_by_wazuh, observation_status |
| asset_services | asset_id, service_id, relationship_type |
| attack_chains | chain_scenario_id, scan_id, created_at, title, source_bundle_id, risk_level, scenario_basis_status, scenario_basis_violation_reason, scenario_basis_summary, current_environment_testable, testability_reason |
| attack_chain_steps | id, chain_id, step_order, step_text, path, location, violation_point, transition_to_next, related_invariants, evidence_ids, threatened_asset_ids |
| attack_chain_invariants | chain_id, invariant_id |
| mitre_attack_flow | id, chain_id, flow_order, tactic, technique, step, reason |
| mitre_flow_invariants | flow_id, invariant_id |
| invariant_impact | id, invariant_id, result_id, scan_id, status, violation_reason, severity, summary, affected_resource_ids, affected_zones |
| asset_events | event_id, scan_id, event_type, asset_id, asset_name, summary, description, zone, severity, evidence_ids, occurred_at, created_at |
| asset_history_monthly | id, company_id, month, date_label, period_start, asset_count, observed_asset_count, review_required_count, violated_invariant_count, total, vulnerable, vulnerable_hw, vulnerable_sw, vulnerable_cred, vulnerable_api, offline, patch_pct, patch_pct_hw, patch_pct_sw, unregistered, new_assets, policy_violations |
| scan_coverage | scan_id, metric, value, attack_phase, total_weight, violated_weight, coverage_pct |
| scan_severity_distribution | scan_id, severity, count |
| scan_zone_violations | scan_id, zone, count |
| scan_type_violations | scan_id, type_name, count |
| remediations | id, invariant_id, scan_id, description, attack_phase, priority, done, updated_at |
| pentest_results | test_id, schema_version, scan_id, scenario_id, tester, tested_at, overall_verdict, attack_input_and_process, observed_result, impact_assessment, evidence_description, additional_notes |

전체 schema 원문은 함께 생성한 JSON `GCP_AI_OUTPUT_FRONTEND_SERVING_CONTRACT.source.json`의 `db_schema`를 보면 된다.

## 21. 현재 raw evidence 상태
- path: `/opt/argos/security/evidence_output/argos-asset-evidence-v1.jsonl`
- rows: `42,580`
- size_bytes: `145,957,724`

상위 event_type:
| event_type | count |
| --- | --- |
| log_trace_state | 22,469 |
| aggregation_state | 19,271 |
| gateway_access_event | 163 |
| data_access_event | 101 |
| api_authorization_event | 100 |
| token_policy_state | 86 |
| authz_policy_state | 86 |
| key_management_state | 86 |
| wazuh_alert_event | 66 |
| central_job_metadata | 51 |
| unknown | 46 |
| privileged_access_event | 43 |
| network_policy_state | 3 |
| account_state_event | 2 |
| privileged_access_state | 2 |
| object_storage_access_event | 2 |
| token_validation_event | 1 |
| identity_auth_event | 1 |
| log_retention_state | 1 |

scenario_scope:
| scenario_scope | count |
| --- | --- |
| scenario3 | 237 |

producer_vm:
| producer_vm | count |
| --- | --- |
| argos-security | 41,813 |
| argos-ops | 445 |
| argos-dmz | 166 |
| argos-data | 105 |
| unknown | 46 |
| argos-mgmt | 5 |

## 22. 시나리오2 확장 대비 field 계약
`시나리오2_최종_구축_피드백안.md` 기준으로, 앞으로 collector가 추가되면 아래 event_type/field가 들어올 수 있다. 프론트는 이 필드들을 optional로 설계하고, 없을 때는 오류가 아니라 `collector gap` 또는 `evidence 없음`으로 표시한다.
| event_type | 현재 GCP count | 프론트 활용 |
| --- | --- | --- |
| firmware_catalog_state | 0 | firmware 등록/승인/허용 범위/서명 상태 |
| firmware_register_event | 0 | firmware 등록 runtime event |
| ota_policy_event | 0 | OTA 정책 변경/승인/대상 범위 |
| firmware_signing_event | 0 | signing workflow, key 위치, caller 허용 여부 |
| device_update_event | 0 | 기기 다운로드/검증/적용/거부 결과 |
| file_distribution_state | 0 | 동일 file_hash 다중 배포, 내부 배포 지점화 |

| field | 현재 GCP count | 설명/화면 활용 |
| --- | --- | --- |
| scenario_scope | 237 | 예: ["scenario2"]. 시나리오 필터와 collector gap 판단 |
| trace_id | 0 | 요청/작업 흐름 연결. evidence chain의 기본 join key |
| request_id | 0 | 단일 요청 식별. API/log correlation |
| event_chain_id | 0 | 시나리오2처럼 여러 event를 체인으로 묶는 join key |
| deployment_id | 0 | OTA campaign/deployment 식별 |
| firmware_id | 0 | firmware catalog 식별자 |
| firmware_hash | 0 | firmware 무결성/승인 여부 연결값 |
| file_hash | 0 | 업로드/서명/배포/기기 적용을 연결하는 파일 hash |
| device_id | 0 | 기기 식별자. 실제 값 노출이 민감하면 hash/alias 사용 |
| device_group | 0 | OTA 대상 그룹 |
| device_model | 0 | OTA 대상 모델 |
| source_asset | 0 | 흐름 출발 자산 |
| dest_asset | 0 | 흐름 도착 자산 |
| actor_id | 279 | 행위 주체. 현재 일부 존재 |
| approver_id | 0 | 승인자 |
| approval_id | 0 | 승인 이력 식별자 |
| approval_status | 0 | approved/missing/rejected/expired 등 |

시나리오2 신규 필드는 먼저 raw evidence의 `observed.*`에 보존되고, backend가 필요한 요약만 `evidenceEvents[]`, `violations[].evidence_details`, `attackChains[]` 또는 별도 detail field로 노출하는 방향이 안전하다. PostgreSQL 물리 컬럼은 실제 샘플이 안정화된 뒤 최소한으로 추가한다.

## 23. 프론트 설계 시 주의사항
- `attackChains[]`는 공식 AI2 결과, `diagnosticRedteamCandidates[]`는 진단용 보조 결과다. 둘을 한 표에 섞지 않는다.
- `mitreTacticMap.mapping_status=missing_or_insufficient_evidence`이면 MITRE 공식 매핑은 없는 것으로 표시한다.
- 위반 상세 팝업은 `summary`만 보여주면 의미가 없다. 최소 `reason`, `judgment_summary`, `evidence_details[].source_ref`, `evidence_details[].event_type`, `trace_id`, `producer_vm`, `observed` 요약을 함께 보여준다.
- `detected_at` 같은 시각 값이 비어 있으면 억지로 빈 label을 만들지 말고 숨긴다. 대신 evidence timestamp가 있으면 그 값을 보여준다.
- 정확한 위반 값이 evidence에 없으면 값을 만들지 말고 `evidence에 구체적 위반 값 미보존`으로 표시한다.
- 새 collector가 붙으면 field가 늘어날 수 있으므로 unknown field는 버리지 말고 세부 보기에서 JSON 확장 영역으로 표시할 수 있게 한다.
- 점검 시작 버튼은 `GET /api/scans/start/status`로 running 여부 확인 후 `POST /api/scans/start`를 호출한다. running이면 버튼 비활성화와 elapsed/snapshot size만 표시한다.

## 24. 프론트 담당자에게 권장하는 최소 화면 단위
1. 점검 목록: `/api/scans` row + `/api/scans/start/status`
2. 점검 요약: `details.summary`, `scanCoverageMetrics`, severity/zone/type distributions
3. 불변식 목록: `details.invariants`
4. 위반 목록/상세: `details.violations` + `evidence_details`
5. 자산/서비스: `details.assets`, `details.services`, `assetReviewQueue`
6. 공식 체인: `details.attackChains`
7. 진단용 후보: `details.diagnosticRedteamCandidates`, `diagnosticMitreTacticMap`
8. Evidence 탐색: `details.evidenceEvents`와 위반별 evidence detail

## 25. 함께 제공되는 원천 JSON
이 문서와 같은 위치에 `GCP_AI_OUTPUT_FRONTEND_SERVING_CONTRACT.source.json`을 생성했다. 프론트 담당 에이전트는 이 JSON에서 실제 sample value, API shape, DB schema, AI export table count를 기계적으로 읽을 수 있다.
