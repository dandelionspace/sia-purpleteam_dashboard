-- =============================================================================
-- Invariants INSERT
-- description: 각 파일의 **정의** 섹션 텍스트 기준 (마크다운 백틱 제거)
-- 공통 불변식(INV-STD-*, INV-ARG-01~08): 시나리오 4 파일 정의 기준
-- INV-STD-13, INV-ARG-08: 시나리오 3 파일 정의 기준
-- INV-STD-CAND-WEB-*, INV-ARG-S2-*: 시나리오 2 파일 목록 텍스트 기준 (정의 섹션 없음)
-- INV-ARG-S3-*: 시나리오 3 파일 정의 기준
-- INV-ARG-S4-*: 시나리오 4 파일 정의 기준
-- =============================================================================

INSERT INTO invariants (invariant_id, description, invariant_source) VALUES

-- =============================================================================
-- 고정 불변식 (fixed) — 시나리오 4 파일 정의 기준
-- =============================================================================

('INV-STD-02',
 '관리자, 개발자, 운영자, Device Auth 관리자, 서비스 계정은 업무 수행에 필요한 최소 권한만 가져야 하며, Device Auth 관리, 기기 인증정보 조회, DB 접근, export 권한은 직무와 승인 목적에 따라 분리되어야 한다.',
 'fixed'),

('INV-STD-03',
 'Device Auth Credential, DB Credential, 내부 API Key, 장기 토큰, 기기 인증키는 KMS, Secret Manager, 승인된 credential vault 등 승인된 보관·관리 체계에서만 저장·사용되어야 한다.',
 'fixed'),

('INV-STD-04',
 '관리자 계정, 서비스 계정, 내부 API Key, DB Credential, Device Auth Credential은 정책상 허용된 최대 사용 기간을 초과해 장기간 유지되면 안 되며, 권한 변경 또는 침해 의심 시 즉시 폐기·회전되어야 한다.',
 'fixed'),

('INV-STD-08',
 'Device Auth API, 기기 등록 API, tenant-device 권한 API, 인증정보 조회 API는 승인된 gateway, bastion, 내부 서비스 경로를 통해서만 호출되어야 한다.',
 'fixed'),

('INV-STD-09',
 '기기 식별정보, tenant-device 매핑정보, 고객-기기 연결정보, 영상 이벤트 메타데이터의 대량·순차·반복 조회는 정상 권한이 있더라도 이상행위로 탐지되어야 한다.',
 'fixed'),

('INV-STD-10',
 '외부 접점 접근, 내부 이동, Device Auth 접근, 기기 인증정보 조회, export, egress 이벤트는 요청자, 대상 자산, tenant, 결과, trace_id를 포함해 추적 가능하게 기록되어야 한다.',
 'fixed'),

('INV-STD-11',
 '외부 접점 접근, 내부 이동, 인증 인프라 접근, 중요 데이터 조회, export 관련 로그는 조사 가능 기간 동안 보존되어야 하며 누락·삭제·무단 변경되어서는 안 된다.',
 'fixed'),

('INV-STD-12',
 '운영자, 관리자, Device Auth 담당자가 기기 인증정보, 고객-기기 매핑정보, 영상 이벤트 메타데이터에 접근하려면 승인된 목적, 작업 티켓, 감사 기록이 연결되어야 한다.',
 'fixed'),

-- INV-STD-13: 시나리오 3 파일 정의 기준
('INV-STD-13',
 '개발 환경, 임시 분석 환경, 협력사 분석 환경은 운영 원본 데이터 환경과 분리되어야 하며, 개인 계정 또는 개발용 계정이 운영 원본 데이터에 직접 접근하면 안 된다.',
 'fixed'),

('INV-STD-14',
 'argos-device-auth, Device Auth 관리 기능, argos-data, argos-security, 키 관리 자산, 로그 보존 자산은 승인된 관리자와 허용된 네트워크 경로에서만 접근 가능해야 한다.',
 'fixed'),

-- INV-STD-CAND-WEB-*: 시나리오 2 파일 목록 텍스트 기준 (정의 섹션 없음)
('INV-STD-CAND-WEB-01',
 '인터넷 노출 웹서비스의 웹 프로세스는 승인되지 않은 OS 명령 실행을 수행할 수 없어야 한다.',
 'fixed'),

('INV-STD-CAND-WEB-02',
 '인터넷 노출 웹서비스는 승인되지 않은 실행 파일 또는 스크립트 업로드를 허용하면 안 된다.',
 'fixed'),

('INV-STD-CAND-WEB-03',
 '인터넷 노출 웹서비스의 웹 프로세스는 승인된 경로 외부에 파일을 생성하거나 수정할 수 없어야 한다.',
 'fixed'),

-- =============================================================================
-- 가변 불변식 — 기존 공통 (시나리오 4 파일 정의 기준)
-- =============================================================================

('INV-ARG-01',
 '아르고스 API 요청과 내부 데이터 접근은 요청 주체의 tenant 범위와 대상 리소스의 tenant가 일치하거나, 명시적으로 승인된 cross-tenant 권한이 있을 때만 허용되어야 한다.',
 'custom'),

('INV-ARG-02',
 '사용자와 내부 계정은 본인 소유, 소속 tenant 소유, 또는 명시적으로 공유된 기기·영상·센서 데이터만 조회할 수 있어야 한다.',
 'custom'),

('INV-ARG-05',
 '영상 이벤트 메타데이터, 센서 요약, object URL은 owner/tenant 검증 이후에도 업무 목적에 필요한 최소 필드만 반환되어야 한다.',
 'custom'),

('INV-ARG-06',
 '동일 token, actor, IP, service account가 짧은 시간 안에 다수 owner, tenant, device를 조회하면 정상 권한이 있더라도 이상행위로 탐지되어야 한다.',
 'custom'),

('INV-ARG-07',
 '사용자, tenant, 기기, 영상 이벤트, 기기 인증 상태의 소유·공유 관계는 각 API나 query가 임의로 판단하지 않고 중앙 권한 테이블 또는 권한 서비스 기준으로 검증되어야 한다.',
 'custom'),

-- INV-ARG-08: 시나리오 3 파일 정의 기준
('INV-ARG-08',
 'OTA 대상 deviceId, deploymentGroup, tenant_id, firmwareVersion, updateStatus는 승인된 OTA 관리자 또는 내부 서비스만 조회할 수 있어야 한다.',
 'custom'),

-- =============================================================================
-- 가변 불변식 — 시나리오 2 추가 (시나리오 2 파일 목록 텍스트 기준, 정의 섹션 없음)
-- =============================================================================

('INV-ARG-S2-01',
 'argos-dmz는 승인된 경로 없이 argos-ops, argos-deploy, argos-mgmt, argos-data로 직접 접근할 수 없어야 한다.',
 'custom'),

('INV-ARG-S2-02',
 'argos-signing은 일반 서버에서 직접 접근할 수 없어야 하며, 펌웨어 서명은 승인된 signing workflow를 통해서만 요청되어야 한다.',
 'custom'),

('INV-ARG-S2-03',
 '고객지원 포털 또는 argos-ops 계정은 OTA 캠페인 생성, 펌웨어 교체, 배포 대상 변경을 수행할 수 없어야 한다.',
 'custom'),

('INV-ARG-S2-04',
 '내부 HTTP/IIS/파일 공유 배포 경로는 승인된 파일 해시와 승인된 변경 이력이 있는 파일만 제공해야 하며, 내부 서버가 동일 file_hash를 다수 대상에 제공하는 배포 지점처럼 동작하면 탐지되어야 한다.',
 'custom'),

('INV-ARG-S2-05',
 'OTA 서버는 승인된 CI/CD 산출물, 승인된 firmware hash, 유효한 펌웨어 서명값을 모두 만족하는 파일만 배포해야 한다.',
 'custom'),

('INV-ARG-S2-06',
 '펌웨어 서명키는 argos-signing 또는 승인된 KMS/HSM에서만 사용되어야 하며 argos-ops, argos-dmz, Git, CI 로그, 개발자 PC에 노출되면 안 된다.',
 'custom'),

('INV-ARG-S2-07',
 'OTA 배포 대상 tenant_id, device group, device model은 해당 펌웨어의 허용 범위를 벗어나면 안 된다.',
 'custom'),

('INV-ARG-S2-08',
 '고위험 OTA 정책 변경은 승인 이력 없이 적용되면 안 된다.',
 'custom'),

('INV-ARG-S2-09',
 '기기는 서명 검증 실패, 승인되지 않은 OTA 캠페인, rollback 정책 위반 펌웨어를 다운로드하거나 적용하면 안 된다.',
 'custom'),

('INV-ARG-S2-10',
 'argos-security는 웹 침해, 내부 정찰, credential 오용, 비인가 파일 생성, 내부 배포 지점화, 펌웨어 등록, 서명, 정책 변경, 기기 다운로드 이벤트를 trace_id, deployment_id, file_hash로 연결할 수 있어야 한다.',
 'custom'),

('INV-ARG-S2-11',
 'OTA 관리자, 배포 서비스 계정, 관리 계정은 argos-dmz, 고객지원 포털, 웹 프로세스 출처에서 인증 성공하거나 고위험 작업을 수행할 수 없어야 한다.',
 'custom'),

('INV-ARG-S2-12',
 '내부 HTTP/IIS/파일 공유 배포 경로 또는 argos-ops 출처 파일은 정식 firmware catalog 또는 CI/CD artifact registry 등록 없이 OTA 배포 경로에 유입되면 안 된다.',
 'custom'),

('INV-ARG-S2-13',
 '고위험 OTA 정책 변경은 작업 실행자와 승인자가 동일하면 안 된다.',
 'custom'),

-- =============================================================================
-- 가변 불변식 — 시나리오 3 추가 (시나리오 3 파일 정의 기준)
-- =============================================================================

('INV-ARG-S3-01',
 '분석 계정, 협력사 분석 계정, 개발자 분석 계정, service account의 대화형 로그인은 MFA 성공과 허용된 IP·국가·VPN·관리 기기 조건을 만족해야만 성공해야 한다.',
 'custom'),

('INV-ARG-S3-05',
 '분석 데이터 export, object storage 저장, 대량 download는 승인된 작업 티켓, 중앙 job metadata, 목적 코드, 승인자 정보가 있어야만 수행되어야 한다.',
 'custom'),

('INV-ARG-S3-06',
 '고객 식별정보, 연락처, 주소, 설치 위치, device_id, video_event_id, raw object key, tenant 분석 데이터, 센서 요약 등 고위험 필드는 masking, aggregation, 최소 필드 정책 또는 별도 승인 조건 없이 export되면 안 된다.',
 'custom'),

('INV-ARG-S3-07',
 'MFA 실패 후 성공, 해외 IP, 미승인 장치, 평소와 다른 시간대, 신규 ASN, 장기 미사용 계정 로그인 이후 대량 query, export, download가 발생하면 argos-security에서 탐지 또는 차단되어야 한다.',
 'custom'),

('INV-ARG-S3-08',
 '분석 계정 로그인부터 권한 판단, query 실행, export job 생성, object storage 기록, download까지의 Evidence는 trace_id, job_id, export_id, actor_id 중 하나 이상의 공통 키로 연결 가능해야 한다.',
 'custom'),

-- =============================================================================
-- 가변 불변식 — 시나리오 4 추가 (시나리오 4 파일 정의 기준)
-- =============================================================================

('INV-ARG-S4-01',
 'argos-dmz 또는 외부 접점 서버는 승인된 네트워크 경로, Bastion, Gateway 정책 없이 관리망·운영망·Device Auth·데이터망으로 직접 이동할 수 없어야 한다.',
 'custom'),

('INV-ARG-S4-02',
 'Device Auth credential, 기기 인증키, 장기 API Key, 서비스 토큰, DB 접속정보는 승인된 보관 체계에서만 관리되어야 하며 평문 또는 비승인 위치에 존재하면 안 된다.',
 'custom'),

('INV-ARG-S4-03',
 'Device Auth 서버, 기기 인증 관리 콘솔, 기기 등록 관리 API는 승인된 관리자나 내부 서비스만 접근할 수 있어야 하며, 관리자 접근은 MFA와 허용된 내부 경로를 만족해야 한다.',
 'custom'),

('INV-ARG-S4-04',
 '기기 식별정보, device_id_hash, tenant_id, 고객-기기 매핑정보는 승인 없는 계정에서 대량·순차·반복 조회되면 안 된다.',
 'custom'),

('INV-ARG-S4-05',
 '기기 인증정보 또는 기기 등록 credential은 암호화되지 않은 상태로 저장되면 안 되며, 승인된 KMS, Secret Manager, credential vault, 암호화 저장소 기준으로 보호되어야 한다.',
 'custom'),

('INV-ARG-S4-06',
 '기기 인증정보, tenant-device 매핑정보, 기기 인증 상태를 파일 또는 외부 저장소로 export하려면 승인 티켓, 수행 계정, 목적 코드, 대상 범위, 반출 경로가 사전에 기록되어야 한다.',
 'custom'),

('INV-ARG-S4-07',
 '관리망 또는 운영망에서 Device Auth 방향으로 비정상 접근이 발생하면 argos-security에서 탐지 또는 차단되어야 한다.',
 'custom'),

('INV-ARG-S4-08',
 'Device Auth 접근 로그, API 로그, DB 조회 로그, egress 로그는 동일 trace_id 또는 event_chain_id로 연결 가능해야 한다.',
 'custom'),

('INV-ARG-S4-09',
 'Device Auth 정보 조회와 고객-기기 매핑정보, 영상 이벤트 메타데이터, 센서 요약정보 접근이 같은 trace에서 발생하면 고위험 또는 critical 이벤트로 분류되어야 한다.',
 'custom'),

('INV-ARG-S4-10',
 'argos-dmz가 내부 데이터를 외부로 전송하는 중계 지점처럼 동작할 경우, 어떤 내부 자산에서 시작된 데이터인지, 어디로 전송되었는지, 전송량과 trace_id가 기록되어야 한다.',
 'custom'),

('INV-ARG-S4-11',
 'ARGOS의 VM과 주요 서비스는 역할, 소유자, 네트워크 zone, 실행 서비스, 중요도, 로그 수집 상태가 식별 가능해야 한다.',
 'custom'),

('INV-ARG-S4-12',
 '외부 접점 서버, 관리 서버, 운영 서버, Device Auth 서버에는 승인되지 않은 원격제어 도구, 웹쉘 의심 파일, 은닉 프로세스, 비인가 실행 파일이 존재하면 안 된다.',
 'custom'),

('INV-ARG-S4-13',
 '과거 침해 의심 서버, 장기 미조치 악성 흔적, 조치 지연 자산은 예외 처리로 방치되면 안 되며, 조치 상태와 증적 보존 상태가 관리되어야 한다.',
 'custom'),

-- =============================================================================
-- 시나리오 1 파일에만 있는 추가 불변식 (시나리오 1 파일 정의 기준)
-- =============================================================================

('INV-STD-01',
 '퇴직자, 전직자, 휴직자의 계정·세션·API Key·서비스 토큰은 즉시 비활성화되어야 한다.',
 'fixed'),

('INV-STD-05',
 'JWT와 세션은 서명뿐 아니라 발급자, 발급 이력, 만료 시간, key id, token id, 폐기 여부까지 검증되어야 한다.',
 'fixed'),

('INV-STD-06',
 'JWT, 세션, 쿠키, 인증 헤더 값은 서버 검증 없이 신뢰되면 안 된다.',
 'fixed'),

('INV-STD-07',
 '인증된 사용자라도 요청 대상 리소스의 소유자 또는 권한자인지 매 요청마다 검증해야 한다.',
 'fixed'),

('INV-ARG-03',
 '식별자를 순차 변경하더라도 요청자 권한 밖의 리소스는 응답되면 안 된다.',
 'custom'),

('INV-ARG-04',
 '주소·설치 위치·공동출입정보·기기 위치 정보는 owner/tenant 검증 후에만 응답되어야 한다.',
 'custom')
ON CONFLICT (invariant_id) DO UPDATE SET
    description      = EXCLUDED.description,
    invariant_source = EXCLUDED.invariant_source;
