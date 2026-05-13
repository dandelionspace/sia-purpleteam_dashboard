BEGIN;

WITH zone_map(invariant_id, default_zone) AS (
  VALUES
    -- ── 계정·인증 (ACC) ─────────────────────────────────────────────────────
    -- 퇴직자 계정 비활성화, 권한 초과 → Samba4 AD (argos-mgmt)
    ('INV-STD-ACC-01', 'argos-mgmt'),
    ('INV-STD-ACC-02', 'argos-mgmt'),

    -- tenant·소유권·권한 검증 → FastAPI WAS (argos-ops)
    ('INV-ARG-ACC-01', 'argos-ops'),
    ('INV-ARG-ACC-02', 'argos-ops'),
    ('INV-ARG-ACC-03', 'argos-ops'),

    -- OTA 배포 대상·정책 승인·작업자 분리 → OTA server (argos-deploy)
    ('INV-ARG-ACC-04', 'argos-deploy'),
    ('INV-ARG-ACC-05', 'argos-deploy'),
    ('INV-ARG-ACC-06', 'argos-deploy'),

    -- 분석 계정 MFA → Samba4 AD (argos-mgmt)
    ('INV-ARG-ACC-07', 'argos-mgmt'),

    -- 고객지원/ops 계정의 OTA 작업 제한 → OTA server (argos-deploy)
    ('INV-ARG-ACC-08', 'argos-deploy'),

    -- ── API 보안 (API) ───────────────────────────────────────────────────────
    -- JWT 검증·토큰 변조·IDOR·인가 → FastAPI WAS/Auth (argos-ops)
    ('INV-STD-API-01', 'argos-ops'),
    ('INV-STD-API-02', 'argos-ops'),
    ('INV-STD-API-03', 'argos-ops'),
    ('INV-STD-API-04', 'argos-ops'),

    -- IDOR·소유권·OTA 노출 → FastAPI WAS (argos-ops)
    ('INV-ARG-API-01', 'argos-ops'),
    ('INV-ARG-API-02', 'argos-ops'),
    ('INV-ARG-API-03', 'argos-ops'),
    ('INV-ARG-API-04', 'argos-ops'),

    -- 분석 데이터 export·PII masking·기기 인증정보 반출 → PostgreSQL/MinIO (argos-data)
    ('INV-ARG-API-05', 'argos-data'),
    ('INV-ARG-API-06', 'argos-data'),
    ('INV-ARG-API-07', 'argos-data'),

    -- ── 감사·탐지 (AUD) ──────────────────────────────────────────────────────
    -- 접근 로그·보존 무결성·대량 조회 탐지 → Wazuh/normalizer (argos-security)
    ('INV-STD-AUD-01', 'argos-security'),
    ('INV-STD-AUD-02', 'argos-security'),
    ('INV-STD-AUD-03', 'argos-security'),
    ('INV-STD-AUD-04', 'argos-security'),

    -- 이상행위·비정상 접근·고위험 이벤트·trace 연결 → Wazuh/evidence-store (argos-security)
    ('INV-ARG-AUD-01', 'argos-security'),
    ('INV-ARG-AUD-02', 'argos-security'),
    ('INV-ARG-AUD-03', 'argos-security'),
    ('INV-ARG-AUD-04', 'argos-security'),
    ('INV-ARG-AUD-05', 'argos-security'),
    ('INV-ARG-AUD-06', 'argos-security'),
    ('INV-ARG-AUD-07', 'argos-security'),
    ('INV-ARG-AUD-08', 'argos-security'),
    ('INV-ARG-AUD-09', 'argos-security'),
    ('INV-ARG-AUD-10', 'argos-security'),

    -- ── 인증정보 (CRED) ──────────────────────────────────────────────────────
    -- credential 보관·폐기·회전 → Wazuh 모니터링 (argos-security)
    ('INV-STD-CRED-01', 'argos-security'),
    ('INV-STD-CRED-02', 'argos-security'),

    -- 펌웨어 서명키 보호 → signing key store (argos-signing)
    ('INV-ARG-CRED-01', 'argos-signing'),

    -- Device Auth credential·기기 인증정보 암호화 → Device Auth (argos-iot)
    ('INV-ARG-CRED-02', 'argos-iot'),
    ('INV-ARG-CRED-03', 'argos-iot'),

    -- ── 환경 분리 (ENV) ──────────────────────────────────────────────────────
    -- 개발/운영 데이터 분리 → PostgreSQL/MinIO (argos-data)
    ('INV-STD-ENV-01', 'argos-data'),

    -- DMZ·외부 서버의 내부망 직접 접근 차단 → nginx/WAF/API Gateway (argos-dmz)
    ('INV-ARG-ENV-01', 'argos-dmz'),
    ('INV-ARG-ENV-02', 'argos-dmz'),

    -- 자산 인벤토리 식별 → Wazuh (argos-security)
    ('INV-ARG-ENV-03', 'argos-security'),

    -- ── 시스템 (SYS) ────────────────────────────────────────────────────────
    -- 중요 시스템 접근 제한 → Bastion SSH (argos-mgmt)
    ('INV-STD-SYS-01', 'argos-mgmt'),

    -- 인터넷 노출 웹 서비스 OS 명령·파일 업로드·파일 생성 → nginx/WAF (argos-dmz)
    ('INV-STD-SYS-02', 'argos-dmz'),
    ('INV-STD-SYS-03', 'argos-dmz'),
    ('INV-STD-SYS-04', 'argos-dmz'),

    -- OTA/배포 파일 무결성·서명 검증·펌웨어 배포 → Gitea/Jenkins/OTA (argos-deploy)
    ('INV-ARG-SYS-01', 'argos-deploy'),
    ('INV-ARG-SYS-02', 'argos-deploy'),
    ('INV-ARG-SYS-03', 'argos-deploy'),
    ('INV-ARG-SYS-04', 'argos-deploy'),

    -- argos-signing 서버 접근 제한 → Signing server (argos-signing)
    ('INV-ARG-SYS-05', 'argos-signing'),

    -- OTA 관리자 dmz/고객지원 인증 경로 제한 → OTA server (argos-deploy)
    ('INV-ARG-SYS-06', 'argos-deploy'),

    -- Device Auth 서버 접근 제한 → Device Auth (argos-iot)
    ('INV-ARG-SYS-07', 'argos-iot'),

    -- 비인가 파일·원격제어 도구·웹쉘 탐지 → Wazuh (argos-security)
    ('INV-ARG-SYS-08', 'argos-security')
)
UPDATE invariants AS i
SET default_zone = z.default_zone
FROM zone_map AS z
WHERE i.invariant_id = z.invariant_id;

COMMIT;
