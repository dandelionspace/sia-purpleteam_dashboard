# invariant_id 기준 메타데이터 테이블
# AI 1 출력에는 없는 zone/type/attack_phase/weight 등을 보완하는 용도

INVARIANT_META = {
    "INV-STD-01": {
        "description": "퇴직자 계정 활성 상태 — 로그인 시도 탐지",
        "default_zone": "관리", "type": "접근제어", "attack_phase": "초기침투",
        "mitre_tactic": "TA0001", "mitre_technique": "T1078",
        "weight": 10, "invariant_source": "fixed",
        "remediation": "퇴직 처리 즉시 계정 비활성화 및 모든 인증 토큰 폐기", "priority": "즉시",
    },
    "INV-STD-02": {
        "description": "직무 범위를 초과하는 권한 남용 탐지",
        "default_zone": "운영", "type": "권한", "attack_phase": "권한상승",
        "mitre_tactic": "TA0004", "mitre_technique": "T1078",
        "weight": 7, "invariant_source": "fixed",
        "remediation": "RBAC 재검토 및 최소 권한 원칙 재적용", "priority": "1주",
    },
    "INV-STD-03": {
        "description": "중요 인증정보 비승인 저장소 저장 탐지",
        "default_zone": "개발", "type": "보안정책", "attack_phase": "권한상승",
        "mitre_tactic": "TA0004", "mitre_technique": "T1552",
        "weight": 10, "invariant_source": "fixed",
        "remediation": "서명키 HSM 이관 및 Secret Manager 도입", "priority": "즉시",
    },
    "INV-STD-04": {
        "description": "퇴사자 관련 키 회전 미비 탐지",
        "default_zone": "관리", "type": "보안정책", "attack_phase": "권한상승",
        "mitre_tactic": "TA0004", "mitre_technique": "T1552",
        "weight": 7, "invariant_source": "fixed",
        "remediation": "퇴직 처리 절차에 키 회전 단계 추가", "priority": "1주",
    },
    "INV-STD-05": {
        "description": "인증 서버 외부 발급 토큰 접근 시도",
        "default_zone": "운영", "type": "접근제어", "attack_phase": "초기침투",
        "mitre_tactic": "TA0001", "mitre_technique": "T1078",
        "weight": 10, "invariant_source": "fixed",
        "remediation": "JWT issuer 검증 강화 및 토큰 블랙리스트 도입", "priority": "즉시",
    },
    "INV-STD-06": {
        "description": "토큰 또는 세션 데이터 임의 변조 탐지",
        "default_zone": "운영", "type": "접근제어", "attack_phase": "권한상승",
        "mitre_tactic": "TA0004", "mitre_technique": "T1134",
        "weight": 10, "invariant_source": "fixed",
        "remediation": "서명 기반 토큰 검증 강화 및 무결성 체크 추가", "priority": "즉시",
    },
    "INV-STD-07": {
        "description": "BOLA — 객체 단위 인가 검증 실패 탐지",
        "default_zone": "운영", "type": "접근제어", "attack_phase": "데이터탈취",
        "mitre_tactic": "TA0010", "mitre_technique": "T1213",
        "weight": 10, "invariant_source": "fixed",
        "remediation": "모든 API 엔드포인트에 객체 소유권 검증 로직 추가", "priority": "즉시",
    },
    "INV-STD-08": {
        "description": "비승인 경로를 통한 내부 API 직접 호출",
        "default_zone": "운영", "type": "접근제어", "attack_phase": "초기침투",
        "mitre_tactic": "TA0001", "mitre_technique": "T1190",
        "weight": 7, "invariant_source": "fixed",
        "remediation": "내부 API 엔드포인트 네트워크 격리 및 인증 강제화", "priority": "1주",
    },
    "INV-STD-09": {
        "description": "대량/순차 데이터 조회 탐지 (잠재적 데이터 탈취)",
        "default_zone": "DB", "type": "접근제어", "attack_phase": "데이터탈취",
        "mitre_tactic": "TA0010", "mitre_technique": "T1048",
        "weight": 4, "invariant_source": "variable",
        "remediation": "Rate limiting 및 이상 접근 패턴 감지 도입", "priority": "1개월",
    },
    "INV-STD-10": {
        "description": "감사 로그 내 필수 추적 필드 누락",
        "default_zone": "운영", "type": "보안정책", "attack_phase": "내부이동",
        "mitre_tactic": "TA0005", "mitre_technique": "T1070",
        "weight": 4, "invariant_source": "variable",
        "remediation": "로그 스키마에 actor_id, trace_id 필수 필드 추가", "priority": "1주",
    },
    "INV-STD-11": {
        "description": "침해사고 증거 로그 무단 삭제 또는 수정 시도",
        "default_zone": "운영", "type": "보안정책", "attack_phase": "내부이동",
        "mitre_tactic": "TA0005", "mitre_technique": "T1070",
        "weight": 10, "invariant_source": "fixed",
        "remediation": "WORM 스토리지 도입 및 로그 삭제 권한 제거", "priority": "즉시",
    },
    "INV-STD-12": {
        "description": "사유 또는 승인 없는 민감정보 접근",
        "default_zone": "DB", "type": "접근제어", "attack_phase": "데이터탈취",
        "mitre_tactic": "TA0010", "mitre_technique": "T1213",
        "weight": 7, "invariant_source": "variable",
        "remediation": "민감정보 접근 티켓 시스템 도입 및 사전 승인 절차 강제화", "priority": "1개월",
    },
    "INV-STD-13": {
        "description": "개발 서버에서 운영 환경 데이터 직접 접근",
        "default_zone": "개발", "type": "네트워크", "attack_phase": "내부이동",
        "mitre_tactic": "TA0008", "mitre_technique": "T1021",
        "weight": 10, "invariant_source": "fixed",
        "remediation": "개발/운영 환경 네트워크 완전 분리 및 접근 정책 강화", "priority": "즉시",
    },
    "INV-STD-14": {
        "description": "핵심 시스템(KMS/인증서버/로그설정) 비인가 경로 접근",
        "default_zone": "관리", "type": "접근제어", "attack_phase": "권한상승",
        "mitre_tactic": "TA0004", "mitre_technique": "T1078",
        "weight": 10, "invariant_source": "fixed",
        "remediation": "핵심 시스템 접근 경로 화이트리스트 제한 및 감사 강화", "priority": "즉시",
    },
    "INV-ARG-01": {
        "description": "테넌트(기업) 간 데이터 격리 위반 탐지",
        "default_zone": "운영", "type": "접근제어", "attack_phase": "데이터탈취",
        "mitre_tactic": "TA0010", "mitre_technique": "T1213",
        "weight": 10, "invariant_source": "fixed",
        "remediation": "테넌트 ID 기반 데이터 격리 및 접근 제어 재검토", "priority": "즉시",
    },
    "INV-ARG-02": {
        "description": "디바이스/영상 소유권 또는 공유 권한 없는 접근",
        "default_zone": "운영", "type": "접근제어", "attack_phase": "데이터탈취",
        "mitre_tactic": "TA0010", "mitre_technique": "T1213",
        "weight": 7, "invariant_source": "fixed",
        "remediation": "리소스 접근 시 소유권 및 공유 권한 검증 로직 필수화", "priority": "즉시",
    },
    "INV-ARG-03": {
        "description": "리소스 식별자(ID) 조작을 통한 타 사용자 데이터 접근",
        "default_zone": "운영", "type": "접근제어", "attack_phase": "데이터탈취",
        "mitre_tactic": "TA0010", "mitre_technique": "T1213",
        "weight": 10, "invariant_source": "fixed",
        "remediation": "모든 API에서 파라미터 변조 감지 및 소유권 검증 강화", "priority": "즉시",
    },
    "INV-ARG-04": {
        "description": "주소/위치/출입 정보 무단 조회 시도",
        "default_zone": "운영", "type": "접근제어", "attack_phase": "데이터탈취",
        "mitre_tactic": "TA0010", "mitre_technique": "T1213",
        "weight": 7, "invariant_source": "variable",
        "remediation": "민감 위치 정보 접근에 별도 권한 체계 도입", "priority": "1개월",
    },
    "INV-ARG-05": {
        "description": "영상/센서 메타데이터 응답에 민감 필드 과다 노출",
        "default_zone": "운영", "type": "보안정책", "attack_phase": "데이터탈취",
        "mitre_tactic": "TA0010", "mitre_technique": "T1048",
        "weight": 4, "invariant_source": "variable",
        "remediation": "API 응답 필드 최소화 및 민감 정보 마스킹 적용", "priority": "1개월",
    },
    "INV-ARG-06": {
        "description": "단일 주체의 비정상적인 다수 테넌트/디바이스 순회",
        "default_zone": "운영", "type": "접근제어", "attack_phase": "내부이동",
        "mitre_tactic": "TA0008", "mitre_technique": "T1021",
        "weight": 10, "invariant_source": "fixed",
        "remediation": "이상 접근 패턴 실시간 탐지 및 자동 세션 차단 도입", "priority": "즉시",
    },
    "INV-ARG-07": {
        "description": "중앙 권한 서비스 검증 없이 API 접근",
        "default_zone": "운영", "type": "접근제어", "attack_phase": "초기침투",
        "mitre_tactic": "TA0001", "mitre_technique": "T1190",
        "weight": 7, "invariant_source": "fixed",
        "remediation": "모든 API 게이트웨이에 중앙화된 인가 서비스 통합 필수화", "priority": "1주",
    },
    "INV-ARG-08": {
        "description": "비인가 주체에 OTA 업데이트 정보 노출",
        "default_zone": "배포", "type": "접근제어", "attack_phase": "초기침투",
        "mitre_tactic": "TA0001", "mitre_technique": "T1078",
        "weight": 7, "invariant_source": "variable",
        "remediation": "OTA 관련 엔드포인트 접근 권한을 ota_admin 역할로 제한", "priority": "1주",
    },
}

# AI 1 severity(소문자) → UI severity(대문자) 변환
SEVERITY_MAP = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "none":     "Low",
}

# 내부 IP 대역 → 서버존 매핑 (Evidence producer IP 보완용)
IP_PREFIX_TO_ZONE = {
    "10.10.1": "DMZ",
    "10.10.2": "IoT",
    "10.10.3": "운영",
    "10.10.4": "DB",
    "10.10.5": "배포",
    "10.10.6": "서명",
    "10.10.7": "관리",
    "10.10.8": "보안",
}

TACTIC_NAMES = {
    "TA0043": "정찰",     "TA0042": "리소스 개발", "TA0001": "초기 접근",
    "TA0002": "실행",     "TA0003": "지속성",       "TA0004": "권한 상승",
    "TA0005": "방어 우회", "TA0006": "자격증명 접근","TA0007": "탐색",
    "TA0008": "내부 이동", "TA0009": "수집",         "TA0011": "C2",
    "TA0010": "데이터 탈취","TA0040": "영향",
}

TECHNIQUE_NAMES = {
    "T1078": "유효한 계정 도용",     "T1190": "공개 취약점 악용",
    "T1110": "무차별 대입",          "T1059": "커맨드 인터프리터",
    "T1072": "소프트웨어 배포 도구", "T1505": "서버 소프트웨어 컴포넌트",
    "T1134": "액세스 토큰 조작",     "T1070": "로그 삭제",
    "T1562": "보안 도구 무력화",     "T1552": "자격증명 탈취",
    "T1555": "패스워드 저장소 접근", "T1046": "네트워크 서비스 스캔",
    "T1083": "파일/디렉토리 탐색",   "T1021": "원격 서비스 악용",
    "T1195": "공급망 침해",          "T1213": "정보 저장소 탈취",
    "T1119": "자동 수집",            "T1071": "앱 레이어 프로토콜",
    "T1572": "프로토콜 터널링",      "T1048": "대역 외 탈취",
    "T1041": "C2 채널 탈취",         "T1485": "데이터 파괴",
    "T1491": "변조",
}


def enrich_violation(ai1_result: dict) -> dict:
    """
    AI 1 출력(argos-ai1-invariant-result-v1)에
    invariant 메타데이터를 병합해 UI가 요구하는 형식으로 반환한다.
    """
    inv_id  = ai1_result.get("invariant_id", "")
    meta    = INVARIANT_META.get(inv_id, {})
    sev_raw = ai1_result.get("severity", "medium")
    status  = ai1_result.get("status", "violated")
    # status == applied 이면 violation_reason 은 항상 null
    violation_reason = ai1_result.get("violation_reason") if status == "violated" else None
    return {
        # AI 1 원본 필드
        "result_id":                  ai1_result.get("result_id", ""),
        "invariant_id":               inv_id,
        "confidence":                 ai1_result.get("confidence", 0.0),
        "evidence_ids":               ai1_result.get("evidence_ids", []),
        "asset_ids":                  ai1_result.get("asset_ids", []),
        "status":                     status,
        "violation_reason":           violation_reason,
        "summary":                    ai1_result.get("summary", ""),
        "reason":                     ai1_result.get("reason", ""),
        "current_environment_testable": ai1_result.get("current_environment_testable", False),
        "testability_reason":         ai1_result.get("testability_reason", ""),
        "created_at":                 ai1_result.get("created_at", ""),
        # UI 호환 필드 (메타데이터 보완)
        "id":               inv_id,
        "severity":         SEVERITY_MAP.get(sev_raw.lower(), sev_raw.capitalize()),
        "description":      ai1_result.get("summary", meta.get("description", "")),
        "server_zone":      meta.get("default_zone", "알 수 없음"),
        "type":             meta.get("type", ""),
        "attack_phase":     meta.get("attack_phase", ""),
        "mitre_tactic":     meta.get("mitre_tactic", ""),
        "mitre_technique":  meta.get("mitre_technique", ""),
        "weight":           meta.get("weight", 1),
        "invariant_source": meta.get("invariant_source", "fixed"),
        "detected_at":      ai1_result.get("created_at", ""),
        "remediation":      meta.get("remediation", ""),
        "priority":         meta.get("priority", "1개월"),
    }
