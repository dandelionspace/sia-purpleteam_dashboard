export const scanSummary = {
  scan_id: "SCAN-0047",
  scanned_at: "2025-06-12T14:32:00Z",
  status: "completed",
  summary: {
    total_violations: 47,
    critical_high: 12,
    attack_chains: 8,
  },
};

// AI 1 출력(argos-ai1-invariant-result-v1) + invariant 메타데이터 병합 형식
// status: "violated" | "applied"  (두 값만 허용)
// violation_reason: null(applied 시) | "clear_violation" | "partial_satisfaction" |
//   "not_determined" | "evidence_missing" | "log_trace_gap" |
//   "control_not_observed" | "environment_not_ready"
export const violations = [
  {
    result_id: "ai1-result-001", invariant_id: "INV-ARG-03", confidence: 0.91,
    evidence_ids: ["evd-api-003"], asset_ids: ["user-10000002"],
    status: "violated", violation_reason: "clear_violation",
    summary: "userId 변경 요청에서 타 고객 개인정보가 반환되어 IDOR 방지 불변식이 위반됨.",
    reason: "token_sub=customer_a인데 target_user_id=customer_b의 개인정보가 200 OK 응답으로 반환됨.",
    current_environment_testable: true, testability_reason: "현재 내부 API와 고객 샘플 데이터로 재현 가능함.",
    created_at: "2025-06-12T14:21:03Z",
    // 메타데이터 보완 필드
    id: "INV-ARG-03", severity: "Critical", description: "리소스 식별자(ID) 조작을 통한 타 사용자 데이터 접근",
    server_zone: "운영", type: "접근제어", attack_phase: "데이터탈취",
    mitre_tactic: "TA0010", mitre_technique: "T1213", weight: 10, invariant_source: "fixed",
    detected_at: "2025-06-12T14:21:03Z", remediation: "모든 API에서 파라미터 변조 감지 및 소유권 검증 강화", priority: "즉시",
  },
  {
    result_id: "ai1-result-002", invariant_id: "INV-STD-05", confidence: 0.84,
    evidence_ids: ["evd-auth-001"], asset_ids: ["jwt-key-001", "token-registry"],
    status: "violated", violation_reason: "partial_satisfaction",
    summary: "JWT 서명과 만료 시간 검증은 수행되지만, 정상 발급 이력과 폐기 여부 검증이 확인되지 않아 토큰 검증 불변식이 부분 충족에 그침.",
    reason: "signature_valid와 exp 검증은 확인되었으나 issued_by_auth_server, jti registry, revocation list 검증 Evidence가 없음.",
    current_environment_testable: true, testability_reason: "발급 이력이 없는 jti와 폐기 처리된 jti를 가진 JWT를 만들어 API 접근 여부를 확인할 수 있음.",
    created_at: "2025-06-12T14:21:09Z",
    id: "INV-STD-05", severity: "Critical", description: "인증 서버 외부 발급 토큰 접근 시도",
    server_zone: "운영", type: "접근제어", attack_phase: "초기침투",
    mitre_tactic: "TA0001", mitre_technique: "T1078", weight: 10, invariant_source: "fixed",
    detected_at: "2025-06-12T14:21:09Z", remediation: "JWT issuer 검증 강화 및 토큰 블랙리스트 도입", priority: "즉시",
  },
  {
    result_id: "ai1-result-003", invariant_id: "INV-STD-10", confidence: 0.68,
    evidence_ids: ["evd-gateway-001", "evd-api-001"], asset_ids: ["api-user-detail", "sensitive-api-logs"],
    status: "violated", violation_reason: "not_determined",
    summary: "Gateway와 API 로그는 확인되었으나 DB 접근 로그가 없어 민감 API 로그 상관관계 불변식의 충족 여부를 확인할 수 없음.",
    reason: "trace_id가 Gateway와 API 로그에는 존재하지만 DB 로그 Evidence가 없어 전체 흐름을 연결할 수 없음.",
    current_environment_testable: true, testability_reason: "동일 요청을 재현한 뒤 DB 접근 로그 또는 sensitive_api_logs 테이블의 trace_id 기록 여부를 확인하면 점검 가능함.",
    created_at: "2025-06-12T14:21:15Z",
    id: "INV-STD-10", severity: "Medium", description: "감사 로그 내 필수 추적 필드 누락",
    server_zone: "운영", type: "보안정책", attack_phase: "내부이동",
    mitre_tactic: "TA0005", mitre_technique: "T1070", weight: 4, invariant_source: "variable",
    detected_at: "2025-06-12T14:21:15Z", remediation: "로그 스키마에 actor_id, trace_id 필수 필드 추가", priority: "1주",
  },
  {
    result_id: "ai1-result-004", invariant_id: "INV-STD-08", confidence: 0.88,
    evidence_ids: ["evd-gateway-002"], asset_ids: ["internal-api-user-detail"],
    status: "violated", violation_reason: "clear_violation",
    summary: "/internal/api/* 경로로의 외부 접근이 Gateway에서 차단되지 않고 통과됨.",
    reason: "DMZ Gateway 로그에 /internal/api/user-detail 요청이 200으로 통과된 기록이 있음.",
    current_environment_testable: true, testability_reason: "외부 IP로 /internal/api/* 요청을 보내 차단 여부를 직접 확인할 수 있음.",
    created_at: "2025-06-12T14:21:22Z",
    id: "INV-STD-08", severity: "High", description: "비승인 경로를 통한 내부 API 직접 호출",
    server_zone: "DMZ", type: "접근제어", attack_phase: "초기침투",
    mitre_tactic: "TA0001", mitre_technique: "T1190", weight: 7, invariant_source: "fixed",
    detected_at: "2025-06-12T14:21:22Z", remediation: "내부 API 엔드포인트 네트워크 격리 및 인증 강제화", priority: "1주",
  },
  {
    result_id: "ai1-result-005", invariant_id: "INV-ARG-01", confidence: 0.95,
    evidence_ids: ["evd-api-005"], asset_ids: ["tenant-a", "tenant-b"],
    status: "violated", violation_reason: "clear_violation",
    summary: "token.tenant_id와 resource.tenant_id가 다른 요청이 허용되어 테넌트 격리 불변식이 위반됨.",
    reason: "token_tenant=tenant-a인데 resource_tenant=tenant-b 자산 조회가 200 OK로 반환됨.",
    current_environment_testable: true, testability_reason: "cross-tenant 요청을 반복해도 차단 여부를 확인할 수 있음.",
    created_at: "2025-06-12T14:21:31Z",
    id: "INV-ARG-01", severity: "Critical", description: "테넌트(기업) 간 데이터 격리 위반 탐지",
    server_zone: "운영", type: "접근제어", attack_phase: "데이터탈취",
    mitre_tactic: "TA0010", mitre_technique: "T1213", weight: 10, invariant_source: "fixed",
    detected_at: "2025-06-12T14:21:31Z", remediation: "테넌트 ID 기반 데이터 격리 및 접근 제어 재검토", priority: "즉시",
  },
  {
    result_id: "ai1-result-006", invariant_id: "INV-STD-03", confidence: 0.79,
    evidence_ids: ["evd-deploy-001"], asset_ids: ["signing-key-001"],
    status: "violated", violation_reason: "evidence_missing",
    summary: "서명키 저장 위치가 HSM 또는 SecretsManager인지 확인할 Evidence가 없어 비승인 저장소 여부를 판단할 수 없음.",
    reason: "서명키 접근 로그가 있으나 저장 위치(HSM vs 파일시스템) 정보가 Evidence에 포함되지 않음.",
    current_environment_testable: true, testability_reason: "배포 서버 파일시스템에 서명키가 존재하는지 직접 확인할 수 있음.",
    created_at: "2025-06-12T14:22:01Z",
    id: "INV-STD-03", severity: "High", description: "중요 인증정보 비승인 저장소 저장 탐지",
    server_zone: "배포", type: "보안정책", attack_phase: "권한상승",
    mitre_tactic: "TA0004", mitre_technique: "T1552", weight: 7, invariant_source: "fixed",
    detected_at: "2025-06-12T14:22:01Z", remediation: "서명키 HSM 이관 및 Secret Manager 도입", priority: "즉시",
  },
  {
    result_id: "ai1-result-007", invariant_id: "INV-ARG-05", confidence: 0.72,
    evidence_ids: ["evd-api-007"], asset_ids: ["video-metadata-api"],
    status: "violated", violation_reason: "partial_satisfaction",
    summary: "영상 메타데이터 API 응답에 minio_object_key 등 내부 경로가 마스킹 없이 노출됨.",
    reason: "응답 JSON에 minio_object_key, thumbnail_url 등 내부 스토리지 경로가 포함되어 있음.",
    current_environment_testable: true, testability_reason: "영상 목록 API를 호출해 응답 필드를 확인할 수 있음.",
    created_at: "2025-06-12T14:22:15Z",
    id: "INV-ARG-05", severity: "Medium", description: "영상/센서 메타데이터 응답에 민감 필드 과다 노출",
    server_zone: "운영", type: "보안정책", attack_phase: "데이터탈취",
    mitre_tactic: "TA0010", mitre_technique: "T1048", weight: 4, invariant_source: "variable",
    detected_at: "2025-06-12T14:22:15Z", remediation: "API 응답 필드 최소화 및 민감 정보 마스킹 적용", priority: "1개월",
  },
];

export const severityDistribution = [
  { name: "Critical", value: 6,  color: "#0C447C" },
  { name: "High",     value: 6,  color: "#185FA5" },
  { name: "Medium",   value: 21, color: "#378ADD" },
  { name: "Low",      value: 14, color: "#85B7EB" },
];

export const zoneViolations = [
  { zone: "DMZ", count: 14 },
  { zone: "운영", count: 11 },
  { zone: "DB", count: 9 },
  { zone: "개발", count: 7 },
  { zone: "배포", count: 4 },
  { zone: "업무", count: 2 },
];

export const typeViolations = [
  { name: "접근제어", value: 16, color: "#0C447C" },
  { name: "네트워크", value: 13, color: "#185FA5" },
  { name: "권한",    value: 10, color: "#378ADD" },
  { name: "보안정책", value: 8,  color: "#85B7EB" },
];

// AI 2 출력(argos-ai2-chain-scenario-v1) 형식
export const attackChains = [
  {
    chain_scenario_id: "chain-scn-001",
    created_at: "2025-06-12T14:30:00Z",
    title: "JWT 정상 발급 이력 검증 누락 기반 위조 토큰 접근 검증 시나리오",
    source_bundle_id: "bundle-001",
    risk_level: "critical",
    scenario_basis: {
      status: "violated",
      violation_reason: "partial_satisfaction",
      summary: "AI 1은 INV-STD-05를 violated로 판단했다. JWT 검증이 완전히 부재한 것이 아니라, 서명과 만료 검증은 확인되지만 정상 발급 이력, jti, 폐기 여부 검증이 확인되지 않은 부분 충족 상태다.",
    },
    current_environment_testable: true,
    testability_reason: "현재 Auth Module, 내부 API, Token Issuance Registry가 있으므로 발급 이력이 없는 JWT 접근 허용 여부를 수동 검증할 수 있다.",
    related_invariants: ["INV-STD-05", "INV-STD-08", "INV-STD-07", "INV-ARG-01", "INV-ARG-03"],
    attack_chain: [
      "과거 JWT 서명키 또는 테스트용 취약 키로 JWT 생성",
      "발급 이력이 없는 jti를 포함한 토큰 구성",
      "DMZ Gateway를 통해 /internal/api/user-detail API 호출",
      "API가 정상 발급 이력 검증 없이 접근을 허용하는지 확인",
      "userId 변경 시 타 고객 데이터 반환 여부 확인",
      "token.tenant_id와 다른 tenant 자산 조회 가능 여부 확인",
    ],
    mitre_attack_flow: [
      { order: 1, tactic: "Credential Access", step: "JWT 서명키 또는 과거 인증키 악용 가능성 확인", related_invariants: ["INV-STD-03", "INV-STD-04", "INV-STD-05"], reason: "정상 발급 이력이 없는 JWT가 허용될 가능성이 확인되었기 때문." },
      { order: 2, tactic: "Initial Access", step: "DMZ Gateway를 통해 내부 API 접근", related_invariants: ["INV-STD-08"], reason: "외부 요청이 /internal/* 경로를 통해 OPS 내부 API로 전달될 수 있는지 확인해야 하기 때문." },
      { order: 3, tactic: "Defense Evasion", step: "서명만 유효한 JWT를 정상 토큰처럼 사용", related_invariants: ["INV-STD-05", "INV-STD-06"], reason: "발급 이력, jti, kid, 폐기 여부 검증이 누락될 경우 위조 JWT가 정상 토큰처럼 처리될 수 있음." },
      { order: 4, tactic: "Discovery", step: "userId, deviceId, videoId, tenant_id 관계 확인", related_invariants: ["INV-ARG-01", "INV-ARG-07"], reason: "식별자 변경을 통한 접근 가능성을 확인하기 위해 리소스 관계를 파악하는 단계." },
      { order: 5, tactic: "Privilege Escalation", step: "권한 범위를 초과한 리소스 접근 시도", related_invariants: ["INV-STD-07", "INV-ARG-01", "INV-ARG-02"], reason: "인증된 사용자처럼 보이는 토큰으로 타 owner 또는 타 tenant 자산 접근이 가능한지 확인." },
      { order: 6, tactic: "Collection", step: "고객 개인정보, 기기 정보, 영상·센서 메타데이터 조회", related_invariants: ["INV-ARG-03", "INV-ARG-04", "INV-ARG-05"], reason: "실제 피해 자산이 응답으로 반환되는지 확인하는 단계." },
      { order: 7, tactic: "Exfiltration", step: "조회된 민감정보와 메타데이터를 외부로 반출 가능한 형태로 확보", related_invariants: ["INV-STD-10", "INV-ARG-05"], reason: "API 응답으로 반환된 민감정보가 외부 저장 가능한 형태인지 확인." },
      { order: 8, tactic: "Impact", step: "개인정보 유출, tenant 경계 붕괴, 사고 추적성 부족 영향 판단", related_invariants: ["INV-STD-10", "INV-STD-11"], reason: "최종적으로 피해 범위 산정과 사고 대응에 영향을 주는지 판단." },
    ],
    manual_validation_guide: {
      goal: "AI 2가 도출한 공격/진단 체인이 실제 수동 침투에서 재현되는지 확인한다.",
      steps: [
        "과거 JWT 서명키 또는 취약 모드 키로 위조 JWT를 생성한다.",
        "DMZ Gateway를 통해 /internal/api/user-detail API를 호출한다.",
        "userId를 다른 고객 값으로 변경한다.",
        "응답에 타 고객 개인정보가 포함되는지 확인한다.",
        "deviceId 또는 videoId 변경 시 기기·영상 메타데이터가 조회되는지 확인한다.",
        "동일 trace_id 기준 Gateway/Auth/API/DB 로그가 남았는지 확인한다.",
      ],
      success_criteria: [
        "위조 JWT로 내부 API 접근이 성공한다.",
        "token.sub와 다른 userId의 개인정보가 반환된다.",
        "token.tenant_id와 다른 tenant 자산이 반환된다.",
        "대량 또는 순차 조회가 탐지되지 않는다.",
      ],
      evidence_to_collect: ["request_id", "trace_id", "사용한 JWT payload", "호출한 API endpoint", "응답 status_code", "응답에 포함된 민감 필드", "관련 로그 ID"],
      safety_boundary: ["승인된 실습 환경에서만 검증한다.", "synthetic account/resource만 사용한다.", "실제 고객 데이터 접근은 금지한다.", "secret 원문 추출 절차는 포함하지 않는다.", "자동 exploit 또는 destructive test는 수행하지 않는다."],
    },
  },
  // 구형 chain 형식 제거 — AI 2 결과 수신 시 추가됨
  // {chain_scenario_id: "chain-scn-002", ...} 등은 POST /api/ai2/scenarios 로 주입
]; // ← 이 아래의 구형 attackChains 선언(nodes/edges 기반) 제거

// *** 구형 형식 제거 — 아래 코드는 삭제됨 ***
// (nodes, edges, kill_chain, techniques, procedures 기반 체인들은
//  AI 2 출력(argos-ai2-chain-scenario-v1)으로 대체됨)

// mitreMapping은 violations의 mitre_tactic/mitre_technique 필드에서 파생
// (백엔드 scanner.py의 _build_mitre_mapping_from_violations와 동일 로직)
export const mitreMapping = [
  { tactic_id: "TA0043", tactic_name: "정찰",       techniques: [] },
  { tactic_id: "TA0042", tactic_name: "리소스 개발", techniques: [] },
  {
    tactic_id: "TA0001", tactic_name: "초기 접근",
    techniques: [
      { technique_id: "T1078", name: "유효한 계정 도용",  severity: "Critical", violation_ids: ["INV-STD-05"] },
      { technique_id: "T1190", name: "공개 취약점 악용",  severity: "High",     violation_ids: ["INV-STD-08"] },
    ],
  },
  { tactic_id: "TA0002", tactic_name: "실행",       techniques: [] },
  { tactic_id: "TA0003", tactic_name: "지속성",     techniques: [] },
  {
    tactic_id: "TA0004", tactic_name: "권한 상승",
    techniques: [
      { technique_id: "T1552", name: "자격증명 탈취", severity: "High", violation_ids: ["INV-STD-03"] },
    ],
  },
  {
    tactic_id: "TA0005", tactic_name: "방어 우회",
    techniques: [
      { technique_id: "T1070", name: "로그 삭제", severity: "Medium", violation_ids: ["INV-STD-10"] },
    ],
  },
  { tactic_id: "TA0006", tactic_name: "자격증명 접근", techniques: [] },
  { tactic_id: "TA0007", tactic_name: "탐색",          techniques: [] },
  { tactic_id: "TA0008", tactic_name: "내부 이동",      techniques: [] },
  { tactic_id: "TA0009", tactic_name: "수집",           techniques: [] },
  { tactic_id: "TA0011", tactic_name: "C2",             techniques: [] },
  {
    tactic_id: "TA0010", tactic_name: "데이터 탈취",
    techniques: [
      { technique_id: "T1213", name: "정보 저장소 탈취", severity: "Critical", violation_ids: ["INV-ARG-03", "INV-ARG-01"] },
      { technique_id: "T1048", name: "대역 외 탈취",     severity: "Medium",   violation_ids: ["INV-ARG-05"] },
    ],
  },
  { tactic_id: "TA0040", tactic_name: "영향", techniques: [] },
];

export const pentestResults = [
  {
    schema_version: "argos-redteam-result-v3",
    scenario_id: "SCN-001",
    test_id: "RT-001",
    tester: "redteam-01",
    tested_at: "2025-06-12T15:30:00+09:00",
    related_invariants: ["INV-STD-03", "INV-STD-08", "INV-ARG-08"],
    target_assets: [{ asset_type: "ota_server", asset_id: "ASSET-001" }],
    overall_verdict: "reproduced",
    narrative: {
      attack_input_and_process: "서명키 노출 시나리오를 기준으로 위조 JWT를 생성하고 OTA 배포 API(/api/v1/deploy)에 인증 없이 접근했다. 이후 악성 펌웨어 이미지를 서명하여 업로드 엔드포인트에 전송했다.",
      observed_result: "인증 없이 OTA 엔드포인트 접근이 가능했고 펌웨어 업로드 API에서 HTTP 200 OK가 반환됐다. 악성 펌웨어가 정상 업데이트로 등록됨을 확인했다.",
      impact_assessment: "악성 펌웨어 업로드가 가능함을 확인했으며 전체 디바이스 플릿에 배포 가능성 있음. 서명 검증 로직 부재로 인해 공급망 침해 시나리오 완전 재현 성공.",
      evidence_description: "trace_id=trc-001, request_id=req-001, 캡처: dashboard://evidence/scn001-rt001.png, 로그: log-ota-001",
      additional_notes: "서명 검증 로직 부재가 핵심 원인. HSM 도입 전까지 OTA 엔드포인트 IP 화이트리스트 적용 권고.",
    },
  },
  {
    schema_version: "argos-redteam-result-v3",
    scenario_id: "SCN-002",
    test_id: "RT-002",
    tester: "redteam-01",
    tested_at: "2025-06-12T16:10:00+09:00",
    related_invariants: ["INV-STD-05", "INV-STD-07", "INV-ARG-01", "INV-ARG-03"],
    target_assets: [
      { asset_type: "customer_profile", asset_id: "user-10000002" },
      { asset_type: "video_event", asset_id: "vid-00012" },
    ],
    overall_verdict: "partially_reproduced",
    narrative: {
      attack_input_and_process: "과거 키로 위조 JWT를 생성하고 내부 API에 userId 파라미터를 변경하여 요청했다. deviceId 변경을 통한 영상 메타데이터 접근은 이번 테스트에서 미수행.",
      observed_result: "userId 변경 요청에서 HTTP 200 OK가 반환되었고 응답에 타 고객의 이름, 이메일, 주소가 포함됐다. deviceId 변경 요청은 검증하지 않았다.",
      impact_assessment: "타 고객 개인정보 조회 가능함을 확인했다. 영상 메타데이터 유출 여부는 추가 검증이 필요하므로 부분 재현으로 판정.",
      evidence_description: "trace_id=trc-002, request_id=req-002, 관련 로그: log-api-001, log-api-002",
      additional_notes: "deviceId 단계 추가 테스트 필요. 객체 소유권 검증 로직 미구현이 근본 원인.",
    },
  },
];

export const coverage = {
  초기침투: { total_weight: 29, violated_weight: 16, coverage_pct: 45 },
  내부이동: { total_weight: 25, violated_weight: 18, coverage_pct: 30 },
  권한상승: { total_weight: 22, violated_weight: 10, coverage_pct: 55 },
  데이터탈취: { total_weight: 20, violated_weight: 12, coverage_pct: 40 },
};

export const scoreHistory = [
  { scan_id: "SCAN-0042", scanned_at: "2025-01-10", score: 38 },
  { scan_id: "SCAN-0043", scanned_at: "2025-02-14", score: 44 },
  { scan_id: "SCAN-0044", scanned_at: "2025-03-20", score: 41 },
  { scan_id: "SCAN-0045", scanned_at: "2025-04-08", score: 52 },
  { scan_id: "SCAN-0046", scanned_at: "2025-05-15", score: 49 },
  { scan_id: "SCAN-0047", scanned_at: "2025-06-12", score: 58 },
];

// segment: "DMZ" | "내부망" | "폐쇄망"
// patch_status: "적용완료" | "미적용" | "지연" (7일 초과)
// edr: EDR 설치 여부, av: 백신 설치 여부, managed: 자산 등록 여부
// exposed: 인터넷 직접 노출 여부, privilege: "정상" | "과다"
// os_age: OS 출시 후 경과 연수, cvss_max: 연결 violation 중 최고 CVSS
export const assets = [
  //       id              name               type       segment   zone    ip                 os                  os_age online_status cvss_max patch_status edr    av     managed exposed privilege violation_ids              last_seen
  { id: "ASSET-001", name: "ota-server-01",   type: "서버",    segment: "내부망", zone: "배포", ip: "10.10.1.11",     os: "Ubuntu 22.04",   os_age: 3, online_status: "온라인",    cvss_max: 9.8, patch_status: "지연",    edr: false, av: false, managed: true,  exposed: true,  privilege: "과다", violation_ids: ["INV-018", "INV-007"], last_seen: "2025-06-12T14:30:00Z" },
  { id: "ASSET-002", name: "db-primary",      type: "서버",    segment: "내부망", zone: "DB",   ip: "192.168.10.15",  os: "CentOS 7",       os_age: 7, online_status: "온라인",    cvss_max: 8.1, patch_status: "지연",    edr: false, av: true,  managed: true,  exposed: false, privilege: "정상", violation_ids: ["INV-042", "INV-055"], last_seen: "2025-06-12T14:29:00Z" },
  { id: "ASSET-003", name: "dev-server-02",   type: "서버",    segment: "내부망", zone: "개발", ip: "192.168.20.22",  os: "Ubuntu 20.04",   os_age: 5, online_status: "온라인",    cvss_max: 9.1, patch_status: "미적용",  edr: false, av: false, managed: true,  exposed: false, privilege: "과다", violation_ids: ["INV-031", "INV-044"], last_seen: "2025-06-12T14:28:00Z" },
  { id: "ASSET-004", name: "admin-web",       type: "서버",    segment: "내부망", zone: "운영", ip: "10.10.2.5",      os: "Debian 11",      os_age: 4, online_status: "온라인",    cvss_max: 7.5, patch_status: "미적용",  edr: true,  av: true,  managed: true,  exposed: true,  privilege: "정상", violation_ids: ["INV-012", "INV-061"], last_seen: "2025-06-12T14:27:00Z" },
  { id: "ASSET-005", name: "backup-01",       type: "서버",    segment: "내부망", zone: "백업", ip: "192.168.30.10",  os: "Ubuntu 22.04",   os_age: 3, online_status: "온라인",    cvss_max: 5.3, patch_status: "적용완료", edr: true,  av: true,  managed: true,  exposed: false, privilege: "정상", violation_ids: ["INV-038"],            last_seen: "2025-06-12T14:26:00Z" },
  { id: "ASSET-006", name: "mgmt-server",     type: "서버",    segment: "내부망", zone: "관리", ip: "10.0.0.5",       os: "Rocky Linux 9",  os_age: 1, online_status: "온라인",    cvss_max: 5.9, patch_status: "적용완료", edr: true,  av: true,  managed: true,  exposed: false, privilege: "정상", violation_ids: ["INV-029"],            last_seen: "2025-06-12T14:25:00Z" },
  { id: "ASSET-007", name: "api-gateway",     type: "서버",    segment: "DMZ",   zone: "DMZ",  ip: "172.16.1.1",     os: "Ubuntu 22.04",   os_age: 3, online_status: "온라인",    cvss_max: null, patch_status: "적용완료", edr: true,  av: true,  managed: true,  exposed: true,  privilege: "정상", violation_ids: [],                     last_seen: "2025-06-12T14:24:00Z" },
  { id: "ASSET-008", name: "log-server",      type: "서버",    segment: "내부망", zone: "운영", ip: "192.168.40.5",   os: "CentOS 8",       os_age: 5, online_status: "온라인",    cvss_max: null, patch_status: "적용완료", edr: true,  av: true,  managed: true,  exposed: false, privilege: "정상", violation_ids: [],                     last_seen: "2025-06-12T14:23:00Z" },
  { id: "ASSET-009", name: "dev-laptop-kim",  type: "PC",      segment: "내부망", zone: "개발", ip: "192.168.20.101", os: "Windows 11",     os_age: 2, online_status: "온라인",    cvss_max: null, patch_status: "적용완료", edr: true,  av: true,  managed: true,  exposed: false, privilege: "정상", violation_ids: [],                     last_seen: "2025-06-12T13:50:00Z" },
  { id: "ASSET-010", name: "dev-laptop-lee",  type: "PC",      segment: "내부망", zone: "개발", ip: "192.168.20.102", os: "macOS 14",       os_age: 1, online_status: "온라인",    cvss_max: null, patch_status: "적용완료", edr: true,  av: true,  managed: true,  exposed: false, privilege: "정상", violation_ids: [],                     last_seen: "2025-06-12T13:45:00Z" },
  { id: "ASSET-011", name: "ops-workstation", type: "PC",      segment: "내부망", zone: "운영", ip: "10.10.2.100",    os: "Windows 11",     os_age: 2, online_status: "온라인",    cvss_max: null, patch_status: "미적용",  edr: false, av: true,  managed: true,  exposed: false, privilege: "과다", violation_ids: [],                     last_seen: "2025-06-12T13:40:00Z" },
  { id: "ASSET-012", name: "sec-analyst-pc",  type: "PC",      segment: "내부망", zone: "관리", ip: "10.0.0.55",      os: "Ubuntu 22.04",   os_age: 2, online_status: "온라인",    cvss_max: null, patch_status: "적용완료", edr: true,  av: true,  managed: true,  exposed: false, privilege: "정상", violation_ids: [],                     last_seen: "2025-06-12T13:35:00Z" },
  { id: "ASSET-013", name: "build-server-pc", type: "PC",      segment: "내부망", zone: "개발", ip: "192.168.20.103", os: "Windows 10",     os_age: 5, online_status: "오프라인", cvss_max: null, patch_status: "미적용",  edr: false, av: false, managed: true,  exposed: false, privilege: "정상", violation_ids: [],                     last_seen: "2025-06-10T09:00:00Z" },
  { id: "ASSET-014", name: "vehicle-ecu-001", type: "IoT",     segment: "폐쇄망", zone: "운영", ip: "10.20.1.1",      os: "AUTOSAR OS",     os_age: 4, online_status: "온라인",    cvss_max: 7.2, patch_status: "지연",    edr: false, av: false, managed: true,  exposed: false, privilege: "정상", violation_ids: ["INV-007"],            last_seen: "2025-06-12T14:20:00Z" },
  { id: "ASSET-015", name: "vehicle-ecu-002", type: "IoT",     segment: "폐쇄망", zone: "운영", ip: "10.20.1.2",      os: "AUTOSAR OS",     os_age: 4, online_status: "온라인",    cvss_max: null, patch_status: "적용완료", edr: false, av: false, managed: true,  exposed: false, privilege: "정상", violation_ids: [],                     last_seen: "2025-06-12T14:19:00Z" },
  { id: "ASSET-016", name: "dashcam-unit-03", type: "IoT",     segment: "폐쇄망", zone: "운영", ip: "10.20.2.3",      os: "Linux 5.15",     os_age: 3, online_status: "온라인",    cvss_max: 6.5, patch_status: "미적용",  edr: false, av: false, managed: true,  exposed: false, privilege: "정상", violation_ids: ["INV-055"],            last_seen: "2025-06-12T14:18:00Z" },
  { id: "ASSET-017", name: "telematics-gw",   type: "IoT",     segment: "DMZ",   zone: "DMZ",  ip: "172.16.2.5",     os: "QNX 7.1",        os_age: 6, online_status: "온라인",    cvss_max: null, patch_status: "지연",    edr: false, av: false, managed: false, exposed: true,  privilege: "정상", violation_ids: [],                     last_seen: "2025-06-12T14:17:00Z" },
  { id: "ASSET-018", name: "core-switch-01",  type: "네트워크 장비", segment: "DMZ",   zone: "DMZ",  ip: "172.16.0.1",     os: "Cisco IOS 17",   os_age: 3, online_status: "온라인",    cvss_max: null, patch_status: "적용완료", edr: false, av: false, managed: true,  exposed: false, privilege: "정상", violation_ids: [],                     last_seen: "2025-06-12T14:32:00Z" },
  { id: "ASSET-019", name: "fw-dmz-internal", type: "네트워크 장비", segment: "DMZ",   zone: "DMZ",  ip: "172.16.0.2",     os: "Fortinet FortiOS", os_age: 2, online_status: "온라인",  cvss_max: 8.4, patch_status: "미적용",  edr: false, av: false, managed: true,  exposed: true,  privilege: "정상", violation_ids: ["INV-042"],            last_seen: "2025-06-12T14:31:00Z" },
  { id: "ASSET-020", name: "vpn-gateway",     type: "네트워크 장비", segment: "내부망", zone: "관리", ip: "10.0.0.1",       os: "Cisco IOS 17",   os_age: 4, online_status: "오프라인", cvss_max: null, patch_status: "미적용",  edr: false, av: false, managed: false, exposed: true,  privilege: "정상", violation_ids: [],                     last_seen: "2025-06-11T18:00:00Z" },
];

// patch_pct_hw: 하드웨어 패치 적용률(%), patch_pct_sw: 소프트웨어 패치 적용률(%)
// unregistered: 비인가/미등록 자산 수, new_assets: 당월 신규 등록 수
// vulnerable_hw/sw/cred/api: 카테고리별 취약 자산 수
export const assetHistory = [
  { date: "01월", total: 42, vulnerable: 7,  vulnerable_hw: 7,  vulnerable_sw: 3, vulnerable_cred: 2, vulnerable_api: 1, offline: 1, patch_pct: 71, patch_pct_hw: 71, patch_pct_sw: 50, unregistered: 3, new_assets: 0, policy_violations: 8  },
  { date: "02월", total: 44, vulnerable: 8,  vulnerable_hw: 8,  vulnerable_sw: 3, vulnerable_cred: 2, vulnerable_api: 1, offline: 1, patch_pct: 68, patch_pct_hw: 68, patch_pct_sw: 45, unregistered: 4, new_assets: 2, policy_violations: 9  },
  { date: "03월", total: 44, vulnerable: 9,  vulnerable_hw: 9,  vulnerable_sw: 4, vulnerable_cred: 3, vulnerable_api: 1, offline: 1, patch_pct: 65, patch_pct_hw: 65, patch_pct_sw: 40, unregistered: 4, new_assets: 0, policy_violations: 10 },
  { date: "04월", total: 46, vulnerable: 9,  vulnerable_hw: 9,  vulnerable_sw: 5, vulnerable_cred: 3, vulnerable_api: 2, offline: 1, patch_pct: 63, patch_pct_hw: 63, patch_pct_sw: 38, unregistered: 5, new_assets: 2, policy_violations: 12 },
  { date: "05월", total: 47, vulnerable: 10, vulnerable_hw: 10, vulnerable_sw: 5, vulnerable_cred: 3, vulnerable_api: 2, offline: 2, patch_pct: 60, patch_pct_hw: 60, patch_pct_sw: 33, unregistered: 6, new_assets: 1, policy_violations: 14 },
  { date: "06월", total: 48, vulnerable: 11, vulnerable_hw: 11, vulnerable_sw: 6, vulnerable_cred: 3, vulnerable_api: 2, offline: 2, patch_pct: 56, patch_pct_hw: 56, patch_pct_sw: 25, unregistered: 7, new_assets: 1, policy_violations: 16 },
];

export const assetEvents = [
  { id: "EVT-001", type: "신규장비",    asset: "unknown-device-01", desc: "미등록 장비 네트워크 접속 감지 — MAC 00:1A:2B:3C:4D:5E",     zone: "DMZ",  time: "2025-06-12T14:15:00Z", severity: "High"     },
  { id: "EVT-002", type: "정책위반",    asset: "db-primary",        desc: "내부 DB 서버 외부 포트 오픈 감지 (TCP 3306 → 0.0.0.0/0)",    zone: "DB",   time: "2025-06-12T13:40:00Z", severity: "Critical" },
  { id: "EVT-003", type: "비인가접속",  asset: "ota-server-01",     desc: "인증 없는 OTA API 엔드포인트 접근 — /api/update (익명)",       zone: "배포", time: "2025-06-12T13:22:00Z", severity: "Critical" },
  { id: "EVT-004", type: "신규장비",    asset: "rogue-laptop-x",    desc: "미등록 노트북 내부망 Wi-Fi 접속 — DHCP 할당 192.168.20.199", zone: "개발", time: "2025-06-12T12:55:00Z", severity: "Medium"   },
  { id: "EVT-005", type: "정책위반",    asset: "fw-dmz-internal",   desc: "방화벽 규칙 변경 감지 — 비인가 인바운드 포트 허용 (ANY)",     zone: "DMZ",  time: "2025-06-12T11:30:00Z", severity: "High"     },
  { id: "EVT-006", type: "네트워크이동", asset: "ota-server-01",    desc: "DMZ → DB 구간 비정상 횡이동 탐지 — 192.168.10.15:1433",       zone: "DMZ",  time: "2025-06-12T10:48:00Z", severity: "High"     },
  { id: "EVT-007", type: "정책위반",    asset: "admin-web",         desc: "관리자 페이지 외부 IP 접근 감지 — /admin (203.0.113.42)",      zone: "운영", time: "2025-06-11T22:10:00Z", severity: "High"     },
  { id: "EVT-008", type: "비인가접속",  asset: "dev-server-02",     desc: "퇴직 개발자 계정 SSH 로그인 시도 — 5회 실패 후 차단",          zone: "개발", time: "2025-06-11T18:30:00Z", severity: "Medium"   },
];

export const assetPolicies = [
  { id: "POL-001", policy: "내부 DB 외부 접근 불가",    category: "네트워크 격리", severity: "Critical", linked_violations: ["INV-042"],          violating_assets: ["ASSET-002", "ASSET-019"] },
  { id: "POL-002", policy: "EDR 필수 설치 (서버/PC)",   category: "에이전트 보안", severity: "High",     linked_violations: [],                   violating_assets: ["ASSET-001", "ASSET-002", "ASSET-003", "ASSET-011", "ASSET-013"] },
  { id: "POL-003", policy: "패치 7일 이내 적용",        category: "패치 관리",    severity: "High",     linked_violations: ["INV-018", "INV-031"], violating_assets: ["ASSET-001", "ASSET-002", "ASSET-014", "ASSET-017"] },
  { id: "POL-004", policy: "미등록 자산 네트워크 격리", category: "자산 등록",    severity: "Medium",   linked_violations: [],                   violating_assets: ["ASSET-017", "ASSET-020"] },
];

export const remediations = [
  { violation_id: "INV-031", description: "서명키 HSM 이관 및 접근 로그 강화", attack_phase: "권한상승", priority: "즉시", done: false },
  { violation_id: "INV-018", description: "OTA 서버 인증 강제화 (MFA 적용)", attack_phase: "초기침투", priority: "즉시", done: false },
  { violation_id: "INV-042", description: "DMZ-DB 세그멘테이션 방화벽 규칙 추가", attack_phase: "내부이동", priority: "1주", done: false },
  { violation_id: "INV-007", description: "펌웨어 배포 파이프라인 서명 검증 필수화", attack_phase: "내부이동", priority: "1주", done: false },
  { violation_id: "INV-055", description: "고객 영상 데이터 AES-256 암호화 적용", attack_phase: "데이터탈취", priority: "1개월", done: false },
];

// type: OS | 펌웨어 | 플랫폼 | 애플리케이션 | DB
// patch_status: 적용완료 | 미적용 | 지연
// eol: 공식 지원 종료 여부
export const softwareAssets = [
  { id: "SW-001", name: "OTA 배포 플랫폼",       type: "플랫폼",     version: "3.2.1",   linked_asset: "ASSET-001", cve_count: 2, patch_status: "미적용",   eol: false, severity: "High",     violation_ids: ["INV-007"], last_updated: "2025-03-10" },
  { id: "SW-002", name: "블랙박스 펌웨어",        type: "펌웨어",     version: "2.1.3",   linked_asset: "ASSET-014", cve_count: 3, patch_status: "지연",     eol: false, severity: "High",     violation_ids: ["INV-007"], last_updated: "2025-02-20" },
  { id: "SW-003", name: "홈캠 펌웨어",            type: "펌웨어",     version: "1.4.0",   linked_asset: "ASSET-016", cve_count: 1, patch_status: "미적용",   eol: false, severity: "Medium",   violation_ids: ["INV-055"], last_updated: "2025-04-01" },
  { id: "SW-004", name: "Ubuntu 20.04 LTS",       type: "OS",         version: "20.04.6", linked_asset: "ASSET-003", cve_count: 5, patch_status: "미적용",   eol: false, severity: "High",     violation_ids: ["INV-031"], last_updated: "2025-01-15" },
  { id: "SW-005", name: "CentOS 7",               type: "OS",         version: "7.9.2009",linked_asset: "ASSET-002", cve_count: 8, patch_status: "지연",     eol: true,  severity: "Critical", violation_ids: ["INV-042"], last_updated: "2024-11-01" },
  { id: "SW-006", name: "MySQL 5.7",              type: "DB",         version: "5.7.44",  linked_asset: "ASSET-002", cve_count: 4, patch_status: "미적용",   eol: true,  severity: "High",     violation_ids: ["INV-042"], last_updated: "2024-12-10" },
  { id: "SW-007", name: "Nginx",                  type: "애플리케이션", version: "1.18.0", linked_asset: "ASSET-004", cve_count: 2, patch_status: "적용완료", eol: false, severity: "Medium",   violation_ids: [],          last_updated: "2025-05-20" },
  { id: "SW-008", name: "OTA 클라이언트 에이전트", type: "에이전트",   version: "2.0.1",   linked_asset: "ASSET-015", cve_count: 0, patch_status: "적용완료", eol: false, severity: null,       violation_ids: [],          last_updated: "2025-06-01" },
];

// type: 서명키 | 인증서 | 계정 | API 토큰
// storage: HSM | 파일시스템 | 환경변수 | DB
// privilege: 최고 | 과다 | 정상
// status: 위험 | 취약 | 만료임박 | 정상
// severity 기준: exposed → Critical
//               파일시스템 저장 → High (MFA 무관, 파일 읽기만으로 탈취 가능)
//               과다/최고권한 + MFA없음 → High (계정 탈취 시 광범위한 피해)
//               환경변수 저장 → Medium (MFA 무관, 로그·프로세스 검사로 노출)
//               violation 연결 → Medium 이상 / HSM + MFA → null
export const credentialAssets = [
  // CRED-001: exposed:true → Critical / status: 위험
  { id: "CRED-001", name: "OTA 서명키 (RSA-4096)",       type: "서명키",   owner: "배포팀",  storage: "파일시스템", mfa: false, last_rotated: "2024-01-15", expires_at: null,         exposed: true,  privilege: "최고", severity: "Critical", status: "위험",    violation_ids: ["INV-031"] },
  // CRED-002: HSM+MFA+정상 → null이나 violation 연결로 Medium / status: 만료임박
  { id: "CRED-002", name: "블랙박스 디바이스 인증서",     type: "인증서",   owner: "DevOps",  storage: "HSM",       mfa: true,  last_rotated: "2025-03-01", expires_at: "2025-09-01", exposed: false, privilege: "정상", severity: "Medium",   status: "만료임박", violation_ids: ["INV-061"] },
  // CRED-003: 과다권한+MFA없음 → High / status: 취약
  { id: "CRED-003", name: "인프라 관리자 계정",           type: "계정",     owner: "인프라팀", storage: "-",         mfa: false, last_rotated: "2023-11-20", expires_at: null,         exposed: false, privilege: "과다", severity: "High",     status: "취약",    violation_ids: ["INV-031"] },
  // CRED-004: 환경변수+MFA없음 → Medium / status: 만료임박
  { id: "CRED-004", name: "드론 협력사 API 토큰",         type: "API 토큰", owner: "연동팀",  storage: "환경변수",  mfa: false, last_rotated: "2025-01-10", expires_at: "2025-07-10", exposed: false, privilege: "정상", severity: "Medium",   status: "만료임박", violation_ids: ["INV-V010"] },
  // CRED-005: 과다권한+MFA없음 → High / status: 취약
  { id: "CRED-005", name: "DB 마스터 계정",               type: "계정",     owner: "DBA",     storage: "-",         mfa: false, last_rotated: "2024-08-01", expires_at: null,         exposed: false, privilege: "과다", severity: "High",     status: "취약",    violation_ids: ["INV-042"] },
  // CRED-006: 환경변수+MFA없음 → Medium / status: 만료임박
  { id: "CRED-006", name: "자동차 협력사 API 토큰",       type: "API 토큰", owner: "연동팀",  storage: "환경변수",  mfa: false, last_rotated: "2025-02-20", expires_at: "2025-08-20", exposed: false, privilege: "정상", severity: "Medium",   status: "만료임박", violation_ids: [] },
  // CRED-007: HSM+MFA+정상권한 → null / status: 정상
  { id: "CRED-007", name: "웹캠 디바이스 루트 인증서",    type: "인증서",   owner: "보안팀",  storage: "HSM",       mfa: true,  last_rotated: "2025-05-01", expires_at: "2026-05-01", exposed: false, privilege: "정상", severity: null,       status: "정상",    violation_ids: [] },
  // CRED-008: 파일시스템+MFA없음+과다권한 → High / status: 취약
  { id: "CRED-008", name: "CI/CD 배포 키",               type: "서명키",   owner: "개발팀",  storage: "파일시스템", mfa: false, last_rotated: "2024-12-01", expires_at: null,         exposed: false, privilege: "과다", severity: "High",     status: "취약",    violation_ids: [] },
];

// ── SCAN-0046 세부 violations (이전 스캔 — AI 1 형식, 더 많은 위반 항목) ──────
const violations_0046 = [
  ...violations,
  {
    result_id: "ai1-result-008", invariant_id: "INV-STD-07", confidence: 0.93,
    evidence_ids: ["evd-api-008"], asset_ids: ["device-10000003"],
    status: "violated", violation_reason: "clear_violation",
    summary: "deviceId 변경 요청에서 타 고객 기기 정보가 반환되어 BOLA 불변식이 위반됨.",
    reason: "token_sub=customer_a인데 deviceId=device-10000003(owner: customer_c)의 정보가 200 OK로 반환됨.",
    current_environment_testable: true, testability_reason: "기기 목록 API에서 deviceId를 변경해 확인 가능.",
    created_at: "2025-05-15T11:21:03Z",
    id: "INV-STD-07", severity: "Critical", description: "BOLA — 객체 단위 인가 검증 실패 탐지",
    server_zone: "운영", type: "접근제어", attack_phase: "데이터탈취",
    mitre_tactic: "TA0010", mitre_technique: "T1213", weight: 10, invariant_source: "fixed",
    detected_at: "2025-05-15T11:21:03Z", remediation: "모든 API 엔드포인트에 객체 소유권 검증 로직 추가", priority: "즉시",
  },
  {
    result_id: "ai1-result-009", invariant_id: "INV-ARG-06", confidence: 0.81,
    evidence_ids: ["evd-aggregation-001"], asset_ids: ["customer_a"],
    status: "violated", violation_reason: "clear_violation",
    summary: "동일 actor가 60초 내 20개 이상의 서로 다른 테넌트 리소스를 순회하는 패턴이 탐지됨.",
    reason: "customer_a가 60초 내 distinct_tenant_count=5, distinct_device_count=23 조회.",
    current_environment_testable: true, testability_reason: "자동 순회 스크립트로 재현 가능.",
    created_at: "2025-05-15T11:22:00Z",
    id: "INV-ARG-06", severity: "Critical", description: "단일 주체의 비정상적인 다수 테넌트/디바이스 순회",
    server_zone: "운영", type: "접근제어", attack_phase: "내부이동",
    mitre_tactic: "TA0008", mitre_technique: "T1021", weight: 10, invariant_source: "fixed",
    detected_at: "2025-05-15T11:22:00Z", remediation: "이상 접근 패턴 실시간 탐지 및 자동 세션 차단 도입", priority: "즉시",
  },
];

// type: REST | GraphQL | gRPC | WebSocket
// auth: JWT | API Key | OAuth2 | mTLS | 없음
// scope: 내부 | 외부 | 파트너
// status 기준: auth없음 / exposed+!rate_limit → 위험
//             exposed+APIKey / violation 존재 → 취약 / 그 외 → 정상
export const apiAssets = [
  { id: "API-001", name: "OTA 배포 API",            type: "REST",      endpoint: "/api/v1/deploy",        auth: "JWT",     scope: "내부",  exposed: false, rate_limit: true,  version: "v1", linked_asset: "ASSET-001", status: "취약",  violation_ids: ["INV-007"], last_audited: "2025-03-10" },
  { id: "API-002", name: "드론 연동 API",            type: "REST",      endpoint: "/api/v1/drone/sync",    auth: "API Key", scope: "파트너", exposed: true,  rate_limit: false, version: "v1", linked_asset: "ASSET-005", status: "위험",  violation_ids: ["INV-031"], last_audited: "2025-01-15" },
  { id: "API-003", name: "블랙박스 데이터 수집 API",  type: "REST",      endpoint: "/api/v2/blackbox/data", auth: "mTLS",    scope: "내부",  exposed: false, rate_limit: true,  version: "v2", linked_asset: "ASSET-014", status: "정상",  violation_ids: [],          last_audited: "2025-05-01" },
  { id: "API-004", name: "홈캠 스트리밍 API",        type: "WebSocket", endpoint: "/ws/cam/stream",         auth: "JWT",     scope: "외부",  exposed: true,  rate_limit: true,  version: "v1", linked_asset: "ASSET-016", status: "취약",  violation_ids: ["INV-055"], last_audited: "2025-04-01" },
  { id: "API-005", name: "OTA 상태 조회 API",        type: "REST",      endpoint: "/api/v1/ota/status",    auth: "API Key", scope: "파트너", exposed: true,  rate_limit: false, version: "v1", linked_asset: "ASSET-001", status: "위험",  violation_ids: ["INV-007"], last_audited: "2025-02-20" },
  { id: "API-006", name: "차량 데이터 분석 API",     type: "GraphQL",   endpoint: "/graphql",               auth: "OAuth2",  scope: "내부",  exposed: false, rate_limit: true,  version: "v1", linked_asset: "ASSET-003", status: "정상",  violation_ids: [],          last_audited: "2025-05-15" },
  { id: "API-007", name: "관리자 내부 API",          type: "REST",      endpoint: "/api/admin",             auth: "없음",    scope: "내부",  exposed: false, rate_limit: false, version: "v1", linked_asset: "ASSET-002", status: "위험",  violation_ids: ["INV-031"], last_audited: "2024-11-01" },
  { id: "API-008", name: "자동차 협력사 연동 API",   type: "REST",      endpoint: "/api/v1/partner/auto",  auth: "OAuth2",  scope: "파트너", exposed: true,  rate_limit: true,  version: "v1", linked_asset: "ASSET-004", status: "정상",  violation_ids: [],          last_audited: "2025-06-01" },
];

// ── 스캔 목록: 집계 지표만 포함 (항상 전체 로드, 트렌드 차트·스캔 선택기용) ──
export const scanList = [
  { scan_id: "SCAN-0042", scanned_at: "2025-01-10T10:00:00Z", status: "completed",
    metrics: { score: 38, total_violations: 63, critical_high: 18, attack_chains: 11, vulnerable_asset_count: 16, patch_rate: 29 } },
  { scan_id: "SCAN-0043", scanned_at: "2025-02-14T11:00:00Z", status: "completed",
    metrics: { score: 44, total_violations: 58, critical_high: 16, attack_chains: 10, vulnerable_asset_count: 15, patch_rate: 33 } },
  { scan_id: "SCAN-0044", scanned_at: "2025-03-20T09:30:00Z", status: "completed",
    metrics: { score: 41, total_violations: 61, critical_high: 17, attack_chains: 11, vulnerable_asset_count: 14, patch_rate: 31 } },
  { scan_id: "SCAN-0045", scanned_at: "2025-04-08T14:00:00Z", status: "completed",
    metrics: { score: 52, total_violations: 54, critical_high: 14, attack_chains: 9,  vulnerable_asset_count: 13, patch_rate: 38 } },
  { scan_id: "SCAN-0046", scanned_at: "2025-05-15T13:20:00Z", status: "completed",
    metrics: { score: 49, total_violations: 52, critical_high: 15, attack_chains: 9,  vulnerable_asset_count: 13, patch_rate: 42 } },
  { scan_id: "SCAN-0047", scanned_at: "2025-06-12T14:32:00Z", status: "completed",
    metrics: { score: 58, total_violations: 47, critical_high: 12, attack_chains: 8,  vulnerable_asset_count: 11, patch_rate: 55 } },
];

// ── 스캔별 세부 데이터: 선택된 스캔에 대해 on-demand 로드 ──────────────────
// 백엔드 연동 시 GET /scans/:id/details 로 교체 예정
// SCAN-0042 ~ SCAN-0045 는 세부 데이터 미제공 (더미 데이터 범위 외)
export const scanDetails = {
  "SCAN-0047": {
    summary: { total_violations: 47, critical_high: 12, attack_chains: 8 },
    violations,
    severityDistribution,
    zoneViolations,
    typeViolations,
    attackChains,
    mitreMapping,
    pentestResults,
    coverage,
    assets,
    assetHistory,
    assetEvents,
    assetPolicies,
    remediations,
    softwareAssets,
    credentialAssets,
    apiAssets,
  },
  "SCAN-0046": {
    summary: { total_violations: 52, critical_high: 15, attack_chains: 9 },
    violations: violations_0046,
    severityDistribution: [
      { name: "Critical", value: 8,  color: "#0C447C" },
      { name: "High",     value: 7,  color: "#185FA5" },
      { name: "Medium",   value: 23, color: "#378ADD" },
      { name: "Low",      value: 14, color: "#85B7EB" },
    ],
    zoneViolations: [
      { zone: "DMZ", count: 16 }, { zone: "운영", count: 13 }, { zone: "DB", count: 10 },
      { zone: "개발", count: 8 },  { zone: "배포", count: 5 },  { zone: "업무", count: 0 },
    ],
    typeViolations: [
      { name: "접근제어", value: 17, color: "#0C447C" },
      { name: "네트워크", value: 15, color: "#185FA5" },
      { name: "권한",    value: 12, color: "#378ADD" },
      { name: "보안정책", value: 8,  color: "#85B7EB" },
    ],
    attackChains,
    mitreMapping,
    pentestResults: [],
    coverage: {
      초기침투: { total_weight: 29, violated_weight: 20, coverage_pct: 31 },
      내부이동: { total_weight: 25, violated_weight: 21, coverage_pct: 16 },
      권한상승: { total_weight: 22, violated_weight: 14, coverage_pct: 36 },
      데이터탈취: { total_weight: 20, violated_weight: 14, coverage_pct: 30 },
    },
    assets,
    assetHistory,
    assetEvents,
    assetPolicies,
    remediations,
    softwareAssets,
    credentialAssets,
    apiAssets,
  },
};
