# Purple Team Dashboard AI Pack Integration Prompt

아래 프롬프트를 그대로 프론트 팀원 agent에게 전달하세요.

---

## Prompt

당신은 `sia-purpleteam_dashboard` 프론트엔드 저장소를 수정하는 프론트엔드 agent입니다.

대상 저장소:

```text
https://github.com/dandelionspace/sia-purpleteam_dashboard/tree/main
```

이번 작업의 목적은 **퍼플팀 보안 관리자 대시보드**가 AI Pack에서 생성한 최신 보안 분석 결과를 표시할 수 있게 만드는 것입니다.

이번 작업은 **퍼플팀 대시보드가 AI Pack central API를 소비하도록 맞추는 작업**입니다. AI Pack 결과 파일을 브라우저가 직접 읽지 않습니다. 파일 해석과 scan/detail 변환은 AI Pack 내부 `central_api`가 담당합니다.

최종 연결 구조:

```text
argos-security AI Pack
  -> /opt/argos/security/ai_runtime/dashboard_api/latest/*.json 생성
  -> /opt/argos/security/ai_runtime/dashboard_api/index/runs.json 생성
  -> AI Pack central_api 제공
     GET  /api/health
     GET  /api/scans
     GET  /api/scans/{scan_id}/details
     POST /api/scans/trigger
     POST /api/scans/{scan_id}/pentest

Purple Team Dashboard Frontend
  -> AI Pack central_api 또는 사내 reverse proxy API 호출
  -> 보안 관리자 화면에 표시
```

완료 기준은 "프론트 빌드 성공"이 아니라, **AI Pack을 서버에 적용했을 때 퍼플팀 대시보드가 실제 서버 evidence 기반 이력과 최신 AI1/AI2 결과를 API로 받아 표시하는 것**입니다.

역할 분리:

```text
GCP 백엔드 팀:
  VM 서비스 로그와 canonical evidence 생성 환경 유지

AI 설계/AI Pack:
  evidence 읽기, AI1/AI2 실행, 자산 registry 갱신, dashboard payload 생성, central API 제공

퍼플팀 대시보드 프론트:
  AI Pack central API 응답을 기존 화면 구조에 렌더링
```

중요한 구분:

```text
이번 작업 대상:
  Purple Team Dashboard
  보안 관리자, 레드팀, 보안 운영자가 보는 대시보드

이번 작업 대상 아님:
  Argos 가상 기업 서비스 프론트
  DMZ 홈페이지 프론트
  고객/사용자용 웹 화면
  기존 GCP legacy dashboard_front
```

Argos 가상 기업 서비스 프론트는 evidence를 발생시키는 업무 시스템일 뿐입니다. 이 작업에서는 그 프론트의 라우팅, 디자인, Nginx 설정, 서비스 API를 수정하지 마세요.

## 1. 핵심 원칙

기존 퍼플팀 대시보드의 디자인과 큰 구조는 유지합니다.

유지할 것:

```text
src/pages/Dashboard.jsx
src/services/scanService.js
src/components/KpiCards.jsx
src/components/ViolationSection.jsx
src/components/AttackSection.jsx
src/components/PentestSection.jsx
src/components/DefenseSection.jsx
src/components/InvariantSection.jsx
src/components/AssetSection.jsx
src/components/ScanSection.jsx
```

기존 사이드바, scan/detail 중심 흐름, 카드/테이블/섹션형 화면 구조를 크게 바꾸지 마세요. 필요한 필드와 세부 패널을 보강하는 방식으로 진행하세요.

AI Pack이 최신 기준입니다. 기존 mock 데이터가 AI Pack과 충돌하면 AI Pack 기준으로 맞춥니다.

## 2. AI Pack 데이터 기준

운영 환경에서 AI Pack은 `argos-security` 중앙 시스템에서 실행되고, 퍼플팀 대시보드가 읽기 좋은 payload를 생성합니다.

프론트는 실제 서버 파일 경로를 직접 읽지 않습니다. AI Pack central API가 아래 payload를 `GET /api/scans`, `GET /api/scans/{scan_id}/details` 형태로 변환해준다고 가정하고 구현하세요.

중요: 대시보드는 특정 시나리오 문서를 하드코딩하지 않습니다. Scenario 1, 이후 추가될 Scenario 2/3, 또는 실제 기업 운영 검증은 모두 같은 방식으로 들어옵니다.

```text
scenario-specific logs or real operation logs
  -> canonical evidence
  -> AI1 invariant results
  -> AI2 chain reports
  -> dashboard payload
```

따라서 프론트는 `scenario_1`, `쿠팡`, `정답 시나리오` 같은 값을 기준으로 화면을 분기하지 마세요. 화면은 `run_id`, `scan_id`, `invariant_id`, `evidence_ids`, `asset_id`, `chain_scenario_id` 기준으로 동작해야 합니다.

AI Pack의 dashboard payload 역할:

```text
summary
assets
asset_changes
asset_review_queue
asset_invariant_impact
invariant_results
invariant_readiness
ai1_evaluation_trace
ai1_llm_reviews
ai2_chain_scenarios
ai2_chain_reports
mitre_tactic_map
security_posture_point
security_posture_timeline
redteam_validation
ai3_report_input
ai3_report_maker_db_export
invariant_catalog
```

운영 서버의 논리 위치:

```text
/opt/argos/security/ai_runtime/dashboard_api/latest/
```

이 경로는 프론트 UI에 노출하지 마세요. 프론트에서는 API 응답 payload로만 다룹니다.

## 2.1 운영형 evidence 증가 처리

AI Pack은 evidence가 계속 증가하는 운영 환경을 전제로 합니다. 프론트는 raw evidence 전체를 직접 렌더링하려고 하면 안 됩니다.

AI runtime은 다음 방식으로 동작합니다.

```text
첫 실행:
  전체 evidence를 훑어 watermark와 latest state cache 생성

이후 실행:
  마지막 성공 offset 이후 append된 evidence 중심으로 처리
  token/key/authz/network/log retention 등 최신 상태 evidence cache를 함께 포함
  log_trace_state, aggregation_state 같은 고빈도 파생 event는 최신 일부만 AI 입력에 포함
```

운영 상태 파일:

```text
/opt/argos/security/ai_runtime/state/evidence_loader/evidence-loader-state.json
/opt/argos/security/ai_runtime/state/evidence_loader/latest-state-evidence.json
```

프론트가 직접 읽어야 하는 것은 위 state 파일이 아니라 아래 dashboard payload입니다.

```text
security_posture_timeline
security_posture_point
summary
scan-detail
assets
invariant_results
ai2_chain_reports
```

프론트 화면에서는 “raw evidence 전체 개수”보다 아래 운영 지표를 우선 표시하세요.

```text
run_id
scan_id
created_at
asset_count
service_count
violated_invariant_count
applied_invariant_count
changed_asset_count
ai2_chain_scenario_count
new_violations_since_previous_run
resolved_invariants_since_previous_run
```

추가 시나리오가 생겨도 프론트는 새 시나리오 전용 화면을 만들 필요가 없습니다. 새 evidence가 같은 canonical schema와 invariant catalog에 맞게 들어오면 기존 timeline, invariant, asset, chain 화면에서 자연스럽게 누적 표시되어야 합니다.

## 3. 기존 API 구조 유지

현재 프론트의 API 구조는 유지합니다.

```text
GET  /api/scans
GET  /api/scans/{scan_id}/details
POST /api/scans/trigger
GET  /api/invariants
POST /api/invariants
POST /api/ai1/results
POST /api/ai2/scenarios
POST /api/scans/{scan_id}/pentest
```

다만 `GET /api/scans/{scan_id}/details` 응답은 AI Pack payload를 충분히 담을 수 있게 확장하세요.

권장 detail shape:

```json
{
  "scan_id": "SCAN-20260508-001",
  "scanned_at": "2026-05-08T10:00:00Z",
  "status": "completed",
  "summary": {},
  "assets": [],
  "assetChanges": [],
  "assetReviewQueue": [],
  "invariantImpact": [],
  "violations": [],
  "invariantReadiness": [],
  "ai1EvaluationTrace": [],
  "ai1LlmReviews": [],
  "attackChains": [],
  "ai2ChainReports": [],
  "mitreTacticMap": {},
  "securityPostureTimeline": {},
  "pentestResults": [],
  "ai3ReportInput": {},
  "ai3ReportMakerDbExport": {},
  "invariants": []
}
```

기존 컴포넌트가 camelCase를 쓰고 있다면 UI 내부에서는 camelCase로 사용해도 됩니다. 단, adapter에서 AI Pack 원본 필드와의 매핑을 명확히 유지하세요.

## 3.1 AI Pack Central API 연동 지시

AI Pack에는 `central_api`가 포함됩니다. 퍼플팀 대시보드는 AI Pack 내부 JSON 파일을 직접 읽거나 직접 해석하지 말고, 아래 API를 호출하세요.

목표:

```text
AI Pack dashboard_api/latest 파일들
  -> AI Pack central_api
  -> /api/scans, /api/scans/{scan_id}/details 응답
  -> frontend scanService.js
```

AI Pack central API 기본 URL 예시:

```text
http://<argos-security-host>:8000
```

프론트에서는 base URL을 환경변수로 분리하세요.

```text
VITE_AI_PACK_API_BASE_URL=http://<argos-security-host>:8000
```

필수 연동:

```text
GET /api/scans
  scan list를 가져온다.

GET /api/scans/{scan_id}/details
  해당 scan의 summary/assets/AI1/AI2/MITRE/timeline/redteam payload를 가져온다.

POST /api/scans/trigger
  AI Pack 실행을 트리거한다.
  운영에서는 인증/권한이 필요하므로 프론트에는 권한 안내와 실패 상태를 표시한다.

POST /api/scans/{scan_id}/pentest
  Red Team 검증 결과를 저장한다.
  chain_scenario_id, step_id, evidence_ids, affected_asset_ids를 반드시 보존한다.

GET /api/health
  AI Pack central API, latest summary, runs index, last job 상태를 표시한다.
```

퍼플팀 저장소에 별도 백엔드가 이미 있고 반드시 같은 origin으로 묶어야 한다면, 그 백엔드는 AI Pack 파일을 직접 해석하지 말고 단순 reverse proxy 또는 API client 역할만 하세요.

에러 처리:

```text
AI Pack API 연결 실패:
  빈 화면이 아니라 setup_required / disconnected 상태 표시

detail 일부 섹션 없음:
  해당 섹션만 빈 배열/빈 객체 처리

trigger 실행 실패:
  scan status를 failed로 표시하고 health 또는 job 상태의 error message 표시
```

보안 제약:

```text
브라우저에 /opt/argos/security 실제 경로를 그대로 노출하지 말 것.
raw token/secret/password/private key를 반환하지 말 것
redacted context와 evidence_id 중심으로 반환할 것
POST /api/scans/trigger는 운영에서는 인증/권한 체크가 필요하다는 TODO를 남길 것.
```

권장 scan list item:

```json
{
  "scan_id": "ai-run-20260508-100000",
  "snapshot_id": "asset-snapshot-20260508-100000",
  "scanned_at": "2026-05-08T10:00:00Z",
  "status": "completed",
  "asset_count": 58,
  "service_count": 38,
  "total_violations": 19,
  "attack_chains_count": 22,
  "source": "ai_pack"
}
```

권장 scan detail에는 아래 필드를 포함하세요.

```text
summary
assets
assetChanges
assetReviewQueue
invariantImpact
violations
invariantReadiness
ai1EvaluationTrace
ai1LlmReviews
attackChains
ai2ChainReports
mitreTacticMap
securityPostureTimeline
pentestResults
ai3ReportInput
ai3ReportMakerDbExport
invariants
adapterStatus
adapterErrors
```

## 4. 필드 매핑 기준

AI Pack 기준 필드명을 우선합니다.

| 의미 | AI Pack 기준 | 기존/혼용 필드 처리 |
|---|---|---|
| 자산 ID | `asset_id` | `id`, `assetId`는 UI alias만 허용 |
| 자산명 | `asset_name` | `name`은 표시용 alias |
| 자산 유형 | `asset_type` | `type`은 표시용 alias |
| 불변식 ID | `invariant_id` | `id`로 덮어쓰지 말 것 |
| 결과 상태 | `status` | 값은 `applied` 또는 `violated` |
| 위반 사유 | `violation_reason` | `clear_violation`, `partial_satisfaction`, `evidence_missing` 등 |
| 증거 ID | `evidence_ids` | `evidence_refs`와 혼용하지 말고 adapter에서 통합 |
| 영향 자산 | `affected_registry_asset_ids` | `asset_ids`와 함께 표시 |
| 체인 ID | `chain_scenario_id` | `scenario_id`는 Red Team 입력 alias로만 허용 |
| 실행 ID | `run_id` | scan_id와 연결 가능 |
| 시점 | `created_at` | scan list의 `scanned_at`으로 변환 가능 |
| Evidence 유형 | `source.event_type` | UI 표시용 `evidence_type` alias 생성 |

Evidence 원본은 다음 구조를 수용해야 합니다.

```json
{
  "schema_version": "argos-asset-evidence",
  "evidence_id": "evd-s1-authorization-audit-027",
  "collected_at": "2026-05-08T10:00:00Z",
  "source": {
    "vm": "argos-ops",
    "component_id": "argos-ops-api",
    "component_type": "api",
    "source_type": "wazuh_normalized",
    "event_type": "api_authorization_event"
  },
  "producer": {
    "vm": "argos-ops",
    "component_id": "argos-ops-api",
    "component_type": "api",
    "zone": "ops"
  },
  "security_context": {
    "trace_id": "trace-001",
    "request_id": "req-001"
  },
  "actor": {
    "actor_id": "customer-a",
    "actor_role": "customer"
  },
  "access": {
    "endpoint": "/api/videos/video-b/url",
    "method": "GET",
    "status_code": 200,
    "authorization_decision": "allow",
    "owner_check_performed": false,
    "tenant_check_performed": false
  },
  "asset": {
    "asset_id": "video-b",
    "asset_type": "video",
    "resource_owner_id": "customer-b",
    "resource_tenant_id": "tenant-b"
  },
  "control": {},
  "detection": {},
  "observed": {},
  "raw_ref": {
    "source": "wazuh_archives",
    "source_event_type": "api_authorization_event"
  }
}
```

원문 token, secret, password, private key, 개인정보 원문은 UI에 표시하지 마세요. ref, hash, summary, evidence_id만 표시합니다.

## 5. 섹션별 보강 지시

### 5.1 KPI / Overview

`summary`와 `securityPostureTimeline.points[-1].metrics`를 함께 사용하세요.

표시할 KPI:

```text
asset_count
service_count
invariant_total
violated_invariant_count
applied_invariant_count
ai2_chain_scenario_count
changed_asset_count
new_asset_count
missing_asset_observation_count
```

### 5.2 AssetSection

현재 자산 목록만 보여주는 수준에서 다음을 추가하세요.

```text
assets
assetChanges
assetReviewQueue
securityPostureTimeline
assetInvariantImpact
```

필수 화면:

```text
1. 전체 자산 목록
2. 신규/변경 자산 이벤트
3. 미등록 자산 후보 review queue
4. 자산별 연결 evidence
5. 자산별 연결 불변식 위반
6. 자산 추이 타임라인
```

자산 추이는 숫자만 보여주지 말고, 특정 시점을 클릭했을 때 아래 drilldown을 보여주세요.

```text
changed_assets
violated_invariants
new_violations_since_previous_run
resolved_invariants_since_previous_run
```

### 5.3 ViolationSection / AI1

AI1 결과는 단순 위반 목록이 아니라 판단 근거를 보여줘야 합니다.

필수 표시:

```text
invariant_id
status
violation_reason
severity
confidence
summary
reason
evidence_ids
asset_ids
affected_registry_asset_ids
affected_services
affected_zones
current_environment_testable
testability_reason
```

`ai1EvaluationTrace`가 있으면 불변식별로 다음을 표시하세요.

```text
required_evidence_types
matched_evidence_ids
fields_checked
decision_basis
missing_fields
```

관리자가 “AI가 무엇을 보고 판단했는지” 볼 수 있어야 합니다.

### 5.4 MITRE Tactic Map

MITRE는 체인 생성 기준이 아니라 UI 분류 기준입니다.

`mitreTacticMap` payload를 우선 사용하세요.

화면 구조:

```text
active tactic 목록
  -> tactic 하위 violated invariant 목록
  -> invariant 클릭
  -> mapping basis
  -> evidence summaries
  -> affected asset ids
  -> next possible invariants
  -> chain candidate ids
  -> redteam validation focus
```

inactive tactic은 기본 화면에 크게 노출하지 말고 접힌 상태 또는 필터로만 보여주세요.

### 5.5 AttackSection / AI2 Chain Reports

기존 `attack_chain` 문자열 배열만 보여주는 방식은 부족합니다.

`ai2ChainReports.reports[].step_reports[]`를 우선 사용하세요.

각 체인 후보 상세는 보고서 형식으로 보여줘야 합니다.

체인 상세 필수 표시:

```text
chain_scenario_id
title
risk_level
related_invariants
executive_summary
step_reports
```

각 step 표시:

```text
order
location
path
related_invariants
evidence_ids
threatened_asset_ids
finding
chain_transition
redteam_focus
```

UI는 한 줄 텍스트 태그로 몰아넣지 마세요. 보고서형 카드 또는 accordion으로 구성하세요.

권장 step 카드 구조:

```text
Step 1. 접근 지점
  location / path

근거 Evidence
  evidence_ids
  trace_id / request_id가 있으면 표시

위반된 불변식
  related_invariants

공격 가능성
  finding
  chain_transition

영향 자산
  threatened_asset_ids

Red Team 검증 포인트
  redteam_focus
```

### 5.6 PentestSection / Red Team

Red Team 결과 입력 구조는 유지하되 AI2 체인과 확실히 연결하세요.

필수 필드:

```text
test_id
scenario_id
chain_scenario_id
tester
tested_at
related_invariants
target_assets
overall_verdict
narrative.attack_input_and_process
narrative.observed_result
narrative.impact_assessment
narrative.evidence_description
narrative.additional_notes
```

이 결과는 나중에 AI3 report input과 `AI_report_maker` 호환 DB export로 이어질 예정이므로 필드를 삭제하지 마세요.

AI3 보고서 생성기는 현재 다음 DB 테이블 형태를 기준으로 설계되어 있습니다.

```text
pentest_results
pentest_related_invariants
pentest_target_assets
attack_chains
invariants
assets
```

AI Pack은 위 테이블로 바로 옮길 수 있도록 `ai3ReportMakerDbExport`를 제공합니다.

```text
GET /api/scans/{scan_id}/details
  -> ai3ReportInput
  -> ai3ReportMakerDbExport
```

프론트의 Red Team 입력 UI는 아래 매핑을 깨뜨리면 안 됩니다.

| 프론트 입력 의미 | AI Pack/AI3 호환 필드 |
|---|---|
| 검증 ID | `validation_id` 또는 `test_id` -> `pentest_results.test_id` |
| 체인 시나리오 ID | `chain_scenario_id` 또는 `scenario_id` -> `pentest_results.scenario_id` |
| 검증자 | `validated_by` 또는 `tester` -> `pentest_results.tester` |
| 검증 시각 | `created_at` 또는 `tested_at` -> `pentest_results.tested_at` |
| 재현 판정 | `validation_status` 또는 `overall_verdict` -> `pentest_results.overall_verdict` |
| 공격 입력/진행 과정 | `narrative.attack_input_and_process` |
| 관찰 결과 | `narrative.observed_result` |
| 영향 평가 | `narrative.impact_assessment` |
| 증거 설명 | `narrative.evidence_description` |
| 추가 의견 | `narrative.additional_notes` |
| 관련 불변식 | `related_invariants[]` -> `pentest_related_invariants` |
| 대상 자산 | `affected_asset_ids[]` 또는 `target_assets[]` -> `pentest_target_assets` |

`validation_status`는 가능하면 아래 값 중 하나로 저장하세요.

```text
confirmed
partially_reproduced
rejected
in_progress
needs_more_evidence
```

AI Pack은 이를 AI3 보고서 생성기용 `overall_verdict` 값으로 변환합니다.

```text
confirmed              -> reproduced
partially_reproduced   -> partially_reproduced
rejected               -> not_reproduced
in_progress            -> in_progress
needs_more_evidence    -> in_progress
```

AI3 자체 구현, Claude 호출, PDF 생성은 이번 프론트 작업 범위가 아닙니다. 이번 범위는 **나중에 AI3가 읽을 수 있는 Red Team validation 필드를 UI에서 보존하고 표시하는 것**입니다.

### 5.7 InvariantSection

불변식 추가/비활성화 기능은 퍼플팀 대시보드의 핵심 관리 기능입니다.

기존 불변식 추가 폼은 유지하되 다음 상태를 수용하세요.

```text
fixed
custom
active
disabled
approved
draft
```

프론트에서 새 불변식을 추가하면 즉시 AI가 임의 판단하는 구조가 아닙니다. 새 불변식은 catalog에 저장되고, 승인/활성화된 뒤 다음 실행부터 AI1 검증 대상이 됩니다.

## 6. Adapter 구현 지침

프론트 adapter를 구현하세요. AI Pack 파일 해석과 scan/detail API 변환은 AI Pack `central_api`가 이미 담당합니다.

프론트 adapter:

```text
AI Pack central_api /api/scans/{scan_id}/details response
  -> component props
```

가능하면 `src/services/scanService.js`를 크게 바꾸지 말고, 별도 프론트 adapter 파일을 추가하세요.

권장 파일:

```text
src/services/aiPackAdapter.js
```

역할:

```text
AI Pack central_api response
  -> 기존 scan list item
  -> 기존 scan detail object
  -> 각 component props
```

adapter는 다음을 수행해야 합니다.

```text
1. snake_case 원본을 UI camelCase로 변환
2. evidence source.event_type을 evidence_type alias로 제공
3. AI2 chain reports를 AttackSection에서 쓰기 좋은 구조로 제공
4. security posture timeline을 assetHistory와 timeline detail로 제공
5. missing payload는 빈 배열/빈 객체로 안전하게 처리
6. legacy mock-only 필드는 가능한 한 AI Pack 필드에서 파생
```

## 7. AI Pack 기준 더미 응답 예시

프론트 mock mode에서 아래 형태를 기준으로 테스트하세요.

```json
{
  "scan_id": "SCAN-20260508-001",
  "scanned_at": "2026-05-08T10:00:00Z",
  "status": "completed",
  "summary": {
    "asset_count": 58,
    "service_count": 38,
    "violated_invariant_count": 19,
    "attack_chains": 22
  },
  "violations": [
    {
      "result_id": "ai1-result-INV-STD-05",
      "invariant_id": "INV-STD-05",
      "status": "violated",
      "violation_reason": "clear_violation",
      "severity": "high",
      "confidence": 0.96,
      "summary": "정상 발급 절차가 확인되지 않은 토큰 요청이 allow로 처리되었다.",
      "reason": "issued_by_auth_server=false인 요청이 200/allow로 기록되었다.",
      "evidence_ids": ["evd-s1-authorization-audit-027"],
      "asset_ids": ["APP-AUTH-001", "video-b"],
      "affected_registry_asset_ids": ["APP-AUTH-001", "video-b"],
      "affected_services": ["SVC-AUTH-001", "SVC-WAS-001"],
      "affected_zones": ["ops"]
    }
  ],
  "ai2ChainReports": {
    "reports": [
      {
        "chain_scenario_id": "chain-scenario-001",
        "title": "Evidence 기반 체인 후보: token_key_control -> authorization_boundary -> data_exposure",
        "risk_level": "high",
        "executive_summary": "정상 발급 절차가 확인되지 않은 토큰 요청이 보호 API 접근과 연결된다.",
        "related_invariants": ["INV-STD-05", "INV-STD-07", "INV-ARG-01"],
        "step_reports": [
          {
            "order": 1,
            "location": "auth service and token validation boundary",
            "path": "auth/token/key control path",
            "related_invariants": ["INV-STD-05"],
            "evidence_ids": ["evd-s1-authorization-audit-027"],
            "threatened_asset_ids": ["APP-AUTH-001"],
            "finding": "정상 발급 이력이 확인되지 않은 토큰 요청이 allow 처리되었다.",
            "chain_transition": "토큰 검증 공백은 API 인가 경계로 요청을 전달할 수 있다.",
            "redteam_focus": [
              "해당 evidence_id를 재조회한다.",
              "동일 trace_id/request_id의 다음 API 인가 evidence를 확인한다."
            ]
          }
        ]
      }
    ]
  },
  "securityPostureTimeline": {
    "points": [
      {
        "run_id": "ai-run-20260508-100000",
        "created_at": "2026-05-08T10:00:00Z",
        "metrics": {
          "asset_count": 58,
          "service_count": 38,
          "invariant_total": 22,
          "violated_invariant_count": 19,
          "applied_invariant_count": 3,
          "changed_asset_count": 1,
          "ai2_chain_scenario_count": 22
        },
        "changed_assets": [],
        "violated_invariants": [],
        "new_violations_since_previous_run": ["INV-STD-05"],
        "resolved_invariants_since_previous_run": []
      }
    ]
  }
}
```

## 8. 금지 사항

다음은 하지 마세요.

```text
1. 퍼플팀 대시보드 전체 디자인 재작성
2. Argos 가상 기업 프론트 수정
3. DMZ Nginx, dashboard_front legacy 경로 수정
4. AI 내부 파일 경로를 UI에 노출
5. evidence 없이 mock 설명만 하드코딩
6. token, secret, password, private key, 개인정보 원문 표시
7. AI2 체인을 단순 slash 문자열이나 짧은 태그 목록으로만 표시
8. MITRE를 체인 생성 기준인 것처럼 설명
```

## 9. 완료 기준

아래가 모두 충족되면 완료입니다.

```text
1. npm install 성공
2. npm run lint 성공
3. npm run build 성공
4. AI Pack central_api /api/health 응답을 프론트 환경변수 base URL로 확인
5. AI Pack central_api /api/scans 응답을 scanService 또는 API client에서 호출
6. AI Pack central_api /api/scans/{scan_id}/details 응답을 화면 detail shape로 변환
7. 기존 퍼플팀 대시보드 backend가 있다면, 그 backend는 AI Pack API reverse proxy/client로만 사용
8. 기존 scan/detail 화면 흐름 유지
9. AI Pack payload mock 또는 실제 latest payload로 화면 렌더링 가능
10. 자산 추이 timeline 표시
11. AI1 판단 evidence 표시
12. AI2 step_reports 보고서형 표시
13. MITRE tactic map 표시
14. Red Team 결과 입력이 AI2 chain과 연결
15. 불변식 추가/비활성화 UI가 catalog 상태를 수용
```

작업 후 변경 요약에는 다음을 포함하세요.

```text
수정한 파일
추가한 frontend adapter
AI Pack central_api base URL 설정 위치
AI Pack 필드와 기존 프론트 필드 매핑표
AI Pack central_api 호출 테스트 결과
frontend 빌드/테스트 결과
아직 AI Pack central_api가 제공해야 하는 필드
```

---

## 참고: 이 프롬프트의 의도

이 프롬프트는 프론트 agent가 "AI가 만든 결과를 예쁘게 보여주는 화면"을 만드는 것이 아니라, 보안 관리자가 다음 질문에 답할 수 있는 대시보드를 만들도록 유도한다.

```text
어떤 자산이 있는가?
어떤 로그/evidence가 들어왔는가?
어떤 불변식이 위반되었는가?
AI1은 어떤 evidence를 보고 판단했는가?
AI2는 어떤 위반들을 어떤 경로로 연결했는가?
레드팀은 어떤 체인을 어떻게 검증해야 하는가?
검증 결과는 이후 보고서 생성으로 어떻게 이어지는가?
```
