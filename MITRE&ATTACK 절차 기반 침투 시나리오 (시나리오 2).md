# MITRE ATT&CK 절차 기반 아르고스 침투 시나리오

## 시나리오 개요

이 문서는 GWISIN 랜섬웨어 침해 사례의 핵심 흐름인 외부 공개 서버 침해, 내부 정찰, credential 오용, 내부 배포 지점 악용을 아르고스(Argos)의 OTA 악성 펌웨어 배포 체계에 대입한 절차형 공격 시나리오다.

세부 ATT&CK 기술 ID 매핑보다는 MITRE ATT&CK의 전술 흐름을 기준으로 공격 절차를 정리한다.

이 시나리오에서 실제 랜섬웨어 실행, 실제 악성 펌웨어 제작, 실제 기기 감염은 수행하지 않는다. 모든 검증은 synthetic Evidence, 더미 firmware hash, 모의 OTA job, 로그 상태값으로 수행한다.

## 최종 공격 체인

```text
외부 공개 고객지원 포털 또는 웹/API 접점 침해
→ 웹 프로세스 명령 실행·위험 파일 업로드 통제 실패
→ argos-dmz에서 내부망 직접 접근 통제 실패
→ 내부 정찰 및 OTA 배포 자산 식별
→ 서비스 credential 또는 OTA 배포 계정 오용
→ 내부 HTTP/IIS/파일 공유 배포 경로 악용
→ 미승인 파일이 OTA 배포 경로로 유입
→ 펌웨어 서명키 보호 또는 signing workflow 통제 실패
→ OTA 서버의 승인된 CI/CD 산출물·hash·서명 검증 실패
→ OTA 대상 tenant/device group 조작
→ 고위험 OTA 정책 승인 이력·승인자 분리 실패
→ 기기의 서명·캠페인·rollback 검증 실패
→ OTA 등록·서명·정책 변경·기기 다운로드 로그 trace 단절
→ 미승인 펌웨어 배포로 기기 신뢰성 및 기업 tenant 서비스 신뢰성 훼손
```

---

# 1. Reconnaissance / 정찰

공격자는 아르고스의 외부 공개 접점과 OTA 운영 구조를 파악한다.

공격자는 다음 정보를 수집하거나 추정한다.

- 아르고스가 고객지원 포털과 외부 API를 운영한다는 점
- `argos-dmz`가 외부 요청의 관문이라는 점
- `argos-ops`에 고객지원 포털과 내부 운영 API가 있다는 점
- `argos-deploy`가 CI/CD, artifact registry, OTA 배포와 연결된다는 점
- `argos-signing`이 펌웨어 서명 workflow를 담당한다는 점
- OTA 대상 정보에 `deviceId`, `deploymentGroup`, `tenant_id`, `firmwareVersion`, `updateStatus`가 포함된다는 점
- 배포 정책에 긴급 배포, 강제 업데이트, rollout 비율, rollback 정책이 존재한다는 점

이 단계에서 공격자는 GWISIN형 사고처럼 외부 공개 서비스가 내부 배포 체계로 이어질 수 있는 경로를 찾는다.

**관련 불변식**

- INV-ARG-08 OTA 업데이트 대상 정보 비인가 노출 금지
- INV-STD-08 내부 API와 보호 대상 업무 API 승인 경로 외부 직접 호출 금지
- INV-STD-14 중요 시스템 접근 경로 제한

---

# 2. Resource Development / 공격 자원 준비

공격자는 실제 악성 펌웨어를 제작하지 않는다. 실습 환경에서는 더미 파일, 미승인 firmware hash, synthetic OTA job을 공격 자원으로 사용한다.

공격 준비 단계에서 공격자는 다음 자원을 마련한다.

- 승인되지 않은 더미 firmware artifact
- 승인된 catalog에 없는 firmware hash
- 내부 배포 경로에 올릴 수 있는 모의 실행 파일 또는 스크립트 이벤트
- OTA 배포 API 호출에 사용할 수 있는 탈취 또는 오용 계정 후보
- 특정 tenant 또는 device group을 대상으로 하는 모의 배포 정책
- 로그 trace 단절 여부를 확인하기 위한 synthetic `trace_id`와 `deployment_id`

아르고스가 다음 통제를 충분히 수행하지 못하면 공격 준비가 실제 배포 조작으로 이어질 수 있다.

- 웹서비스 위험 파일 업로드 차단 미흡
- 내부 배포 경로의 승인 hash 검증 미흡
- OTA 배포 credential 보호 미흡
- 펌웨어 서명키와 signing workflow 보호 미흡
- artifact registry와 firmware catalog 등록 검증 미흡

**관련 불변식**

- INV-STD-CAND-WEB-02 위험 파일 또는 스크립트 업로드 금지
- INV-STD-03 서비스 credential, OTA 배포 토큰, 펌웨어 서명키 보호
- INV-ARG-S2-04 내부 배포 경로 승인 파일 제한
- INV-ARG-S2-12 내부 배포 경로 파일의 OTA 경로 유입 차단
- INV-ARG-S2-06 펌웨어 서명키 승인 위치 외부 노출 금지

---

# 3. Initial Access / 최초 접근

공격자는 외부에서 접근 가능한 고객지원 포털 또는 웹/API 접점을 통해 `argos-dmz` 또는 `argos-ops`에 영향을 주려 한다.

이 시나리오의 검증 대상은 실제 웹셸 실행이 아니라 다음과 같은 Evidence다.

- 웹 프로세스 하위 OS 명령 실행 시도 이벤트
- 실행 파일 또는 스크립트 업로드 시도 이벤트
- 승인된 업로드 경로 외부 파일 생성·수정 이벤트
- 고객지원 포털 출처의 비정상 파일 이벤트

예시는 다음과 같이 표현한다.

```text
web_request_event:
  source_asset: external_client
  dest_asset: argos-dmz
  action: upload
  file_type: script
  upload_result: allowed
  request_id: req-s2-001
```

이 이벤트가 차단되지 않고 내부 파일 생성 또는 프로세스 실행으로 이어지면 최초 접근 통제가 실패한 상태다.

**관련 불변식**

- INV-STD-CAND-WEB-01 웹 프로세스 OS 명령 실행 금지
- INV-STD-CAND-WEB-02 위험 파일 또는 스크립트 업로드 금지
- INV-STD-CAND-WEB-03 승인 경로 외부 파일 생성·수정 금지
- INV-STD-10 OTA 및 웹 침해 관련 로그 추적

---

# 4. Defense Evasion / 방어 우회

공격자는 외부 침해 이후의 행위를 정상 운영 행위처럼 보이게 하려 한다.

아르고스 환경에서 방어 우회는 다음 방식으로 나타난다.

- 고객지원 포털의 정상 파일 업로드처럼 보이는 요청 사용
- 내부 파일 공유 또는 HTTP/IIS 배포 경로를 정상 운영 배포소처럼 사용
- 테스트 펌웨어 등록 또는 긴급 패치처럼 보이는 OTA job 생성
- 소규모 tenant 또는 제한된 device group 대상 배포로 탐지 회피
- `rollout_100`, `force_update`, `rollback_disable` 같은 고위험 정책을 승인 이력 없이 적용
- 로그가 서로 다른 시스템에 흩어져 trace가 단절된 구간 악용

이 단계에서 공격자는 악성코드 기반 은닉보다 **정상 운영·배포 절차로 위장되는 논리적 통제 실패**를 이용한다.

**관련 불변식**

- INV-ARG-S2-04 내부 배포 경로 승인 파일 제한
- INV-ARG-S2-08 고위험 OTA 정책 변경 승인 이력 필수
- INV-ARG-S2-13 고위험 OTA 정책 실행자와 승인자 분리
- INV-ARG-S2-10 웹 침해부터 기기 다운로드까지 trace 연결
- INV-STD-11 OTA 사고 관련 로그 보존

---

# 5. Credential Access / 인증 수단 악용

공격자는 고객지원 포털 또는 내부 서버에 남아 있는 서비스 credential, OTA 배포 토큰, 관리 계정을 악용하려 한다.

아르고스에서 문제가 되는 credential은 다음과 같다.

- 고객지원 포털 서버의 내부 API credential
- `argos-ops` 서비스 계정
- OTA 관리자 계정
- 배포 서비스 계정
- CI/CD artifact registry 접근 토큰
- signing workflow 요청 권한
- 펌웨어 서명키 또는 서명키 참조값

특히 OTA 관리자, 배포 서비스 계정, 관리 계정이 `argos-dmz`, 고객지원 포털, 웹 프로세스 출처에서 인증 성공하면 내부 침해가 OTA 배포 조작으로 확장될 수 있다.

**관련 불변식**

- INV-STD-02 관리자·개발자·운영자·OTA 배포 계정 최소 권한
- INV-STD-03 서비스 credential, OTA 배포 토큰, 펌웨어 서명키 보호
- INV-STD-04 퇴사자·권한 변경자 credential 폐기 또는 회전
- INV-ARG-S2-11 DMZ·고객지원 포털·웹 프로세스 출처의 중요 계정 인증 성공 금지
- INV-ARG-S2-06 펌웨어 서명키 승인 위치 외부 노출 금지

---

# 6. Discovery / 내부 자산 식별

공격자는 `argos-dmz` 또는 `argos-ops`를 발판으로 내부 자산 구조를 파악한다.

아르고스 환경에서 공격자가 식별하려는 주요 자산은 다음과 같다.

- `argos-ops`
- `argos-deploy`
- `argos-mgmt`
- `argos-data`
- `argos-signing`
- OTA 서버
- CI/CD artifact registry
- firmware catalog
- approved firmware hash 목록
- OTA deployment group
- tenant별 device group
- device model별 firmware 허용 범위
- OTA 관리자 API와 배포 정책 API

정상 구조에서는 `argos-dmz`가 승인된 경로 없이 내부 운영망, 배포망, 관리망, 데이터망으로 직접 접근할 수 없어야 한다.

**관련 불변식**

- INV-ARG-S2-01 `argos-dmz`의 내부망 직접 접근 금지
- INV-ARG-S2-02 `argos-signing` 일반 서버 직접 접근 금지
- INV-STD-08 내부 API와 보호 대상 업무 API 승인 경로 외부 직접 호출 금지
- INV-STD-14 OTA 서버, 배포 서버, 서명 시스템, 로그 시스템 접근 제한
- INV-ARG-08 OTA 업데이트 대상 정보 비인가 노출 금지

---

# 7. Privilege Escalation / 권한 오용 및 권한 범위 확장

공격자는 내부 자산을 식별한 뒤, 확보한 계정이나 서비스 권한을 이용해 OTA 배포 권한 범위를 넓히려 한다.

권한 오용의 예시는 다음과 같다.

- 고객지원 포털 계정으로 OTA 캠페인 생성 시도
- `argos-ops` 서비스 계정으로 펌웨어 교체 시도
- 개발자 계정으로 production OTA 배포 시도
- 배포 서비스 계정으로 대상 tenant 또는 device group 변경
- signing workflow 승인 없이 펌웨어 서명 요청
- 고위험 OTA 정책을 실행자 본인이 승인

아르고스가 역할별 권한 분리와 출처 기반 인증 제한을 수행하지 않으면, 내부 침해는 OTA 운영 권한으로 확장될 수 있다.

**관련 불변식**

- INV-STD-02 관리자·개발자·운영자·OTA 배포 계정 최소 권한
- INV-ARG-S2-03 고객지원 포털 또는 `argos-ops` 계정의 OTA 제어 행위 금지
- INV-ARG-S2-11 DMZ·고객지원 포털·웹 프로세스 출처의 중요 계정 인증 성공 금지
- INV-ARG-S2-02 `argos-signing` 직접 접근 금지 및 signing workflow 강제
- INV-ARG-S2-13 고위험 OTA 정책 작업 실행자와 승인자 분리

---

# 8. Collection / 배포 대상 및 펌웨어 정보 수집

공격자는 OTA 배포를 정교하게 만들기 위해 대상 정보를 수집한다.

## 8.1 OTA 대상 정보 수집

공격자는 OTA 대상 조회 API 또는 관리자 화면을 통해 다음 정보를 확인하려 한다.

```http
GET /internal/api/ota-targets?deploymentGroup=enterprise-camera-test
GET /admin/ota/deployments?tenant_id=tenant-alpha
```

수집 가능한 정보:

- `deviceId`
- `deploymentGroup`
- `tenant_id`
- `firmwareVersion`
- `updateStatus`
- device model
- rollout 상태

## 8.2 펌웨어 catalog 정보 수집

공격자는 firmware catalog와 artifact registry 상태를 확인하려 한다.

수집 가능한 정보:

- `firmware_id`
- `firmware_hash`
- 승인된 firmware hash 여부
- artifact registry 등록 여부
- signature status
- allowed tenant 목록
- allowed device model 목록

## 8.3 배포 정책 정보 수집

공격자는 OTA 배포 정책과 고위험 옵션을 확인한다.

수집 가능한 정보:

- rollout 비율
- 긴급 배포 여부
- 강제 업데이트 여부
- rollback disable 여부
- 승인자 정보
- 변경 승인 이력

**관련 불변식**

- INV-ARG-08 OTA 업데이트 대상 정보 비인가 노출 금지
- INV-ARG-S2-07 OTA 배포 대상 tenant·device group·device model 범위 검증
- INV-ARG-S2-08 고위험 OTA 정책 변경 승인 이력 필수
- INV-ARG-S2-13 고위험 OTA 정책 실행자와 승인자 분리
- INV-STD-10 OTA 관리자 API와 배포 API 로그 기록

---

# 9. Command and Control / OTA 배포 흐름 제어

이 시나리오에서는 전통적인 악성코드 C2가 아니라, 공격자가 정상 OTA 관리 기능과 내부 배포 경로를 오용해 배포 흐름을 제어하는 형태로 해석한다.

공격자는 다음 방식으로 OTA 배포 흐름을 조작하려 한다.

- 내부 HTTP/IIS/파일 공유 배포 경로에 미승인 파일 제공
- 미승인 파일을 OTA 배포 경로로 유입
- firmware catalog 또는 artifact registry 등록 검증 우회
- 승인되지 않은 firmware hash를 OTA 서버에 등록
- signing workflow 승인 없이 서명 요청
- 특정 tenant 또는 device group으로 배포 대상 제한
- 긴급 배포 또는 강제 업데이트 정책 활성화
- 100% rollout 또는 rollback disable 활성화

실습 환경에서는 실제 악성 펌웨어 배포 대신, 더미 firmware hash와 mock device update event로 검증한다.

**관련 불변식**

- INV-ARG-S2-04 내부 배포 경로 승인 파일 제한
- INV-ARG-S2-12 내부 배포 경로 파일의 OTA 경로 유입 차단
- INV-ARG-S2-05 승인된 CI/CD 산출물·hash·서명값만 OTA 배포
- INV-ARG-S2-02 `argos-signing` 직접 접근 금지 및 signing workflow 강제
- INV-ARG-S2-08 고위험 OTA 정책 변경 승인 이력 필수
- INV-ARG-S2-13 고위험 OTA 정책 실행자와 승인자 분리

---

# 10. Exfiltration / 승인 경로 밖 산출물 유입 및 로그 단절

이 시나리오의 Exfiltration 단계는 고객 데이터 반출보다 **승인된 배포 경계 밖의 파일과 상태가 OTA 신뢰 경계 안으로 유입되는 현상**으로 해석한다.

공격자는 다음 흐름을 만들려 한다.

- 내부 배포 경로에서 생성된 미승인 파일을 OTA 배포 경로로 이동
- 정식 firmware catalog 또는 artifact registry 등록 없이 OTA 서버에 유입
- 펌웨어 서명키 또는 signing workflow를 승인 경로 밖에서 사용
- 배포 정책 변경 로그와 서명 로그의 연결 단절
- 기기 다운로드 이벤트와 배포 승인 이력의 연결 단절

이 단계에서 핵심은 데이터 반출보다 **배포 신뢰 경계의 붕괴와 사고 추적 불가능성**이다.

**관련 불변식**

- INV-ARG-S2-12 내부 배포 경로 파일의 OTA 경로 유입 차단
- INV-ARG-S2-06 펌웨어 서명키 승인 위치 외부 노출 금지
- INV-ARG-S2-10 웹 침해부터 기기 다운로드까지 trace 연결
- INV-STD-10 OTA 관련 민감 로그 기록
- INV-STD-11 OTA 사고 관련 로그 보존

---

# 11. Impact / 최종 피해

최종적으로 아르고스는 다음 피해를 입을 수 있다.

- 미승인 펌웨어가 OTA 서버에 등록됨
- 승인되지 않은 firmware hash가 배포 대상이 됨
- 펌웨어 서명 또는 서명 검증 신뢰 체계가 훼손됨
- 특정 tenant 또는 device group에 잘못된 업데이트가 배포됨
- 긴급 배포·강제 업데이트·100% rollout으로 피해 범위가 빠르게 확장됨
- rollback disable로 복구가 지연됨
- 홈캠, 블랙박스, 기업용 카메라, 차량·드론용 카메라 모듈의 신뢰성이 훼손됨
- 기업 고객 tenant 서비스 신뢰성이 저하됨
- OTA 등록·서명·배포·다운로드 trace 단절로 원인 분석이 지연됨
- 고객 신뢰 하락 및 규제 대응 부담이 증가함

실습에서는 실제 기기 감염이 아니라, mock device update log에서 미승인 펌웨어 다운로드·적용 시도가 발생했는지 확인한다.

**관련 불변식**

- INV-ARG-S2-05 승인된 CI/CD 산출물·hash·서명값만 OTA 배포
- INV-ARG-S2-07 OTA 배포 대상 tenant·device group·device model 범위 검증
- INV-ARG-S2-08 고위험 OTA 정책 변경 승인 이력 필수
- INV-ARG-S2-09 기기 서명·캠페인·rollback 검증
- INV-ARG-S2-10 웹 침해부터 기기 다운로드까지 trace 연결
- INV-STD-11 OTA 사고 관련 로그 보존

---

# 12. MITRE ATT&CK 절차 매핑 요약

| MITRE ATT&CK 전술 단계 | 아르고스 시나리오 내용 | 관련 불변식 |
|---|---|---|
| Reconnaissance | 외부 고객지원 포털, 웹/API 접점, OTA 대상 조회 API, 배포 구조 파악 | INV-ARG-08, INV-STD-08, INV-STD-14 |
| Resource Development | 더미 firmware artifact, 미승인 firmware hash, 모의 OTA job, 내부 배포 파일 준비 | INV-STD-CAND-WEB-02, INV-ARG-S2-04, INV-ARG-S2-12 |
| Initial Access | 외부 웹서비스를 통해 웹 프로세스 명령 실행, 위험 파일 업로드, 경로 외 파일 생성 시도 | INV-STD-CAND-WEB-01, INV-STD-CAND-WEB-02, INV-STD-CAND-WEB-03 |
| Defense Evasion | 정상 업로드, 내부 배포소, 테스트 배포, 긴급 패치처럼 위장 | INV-ARG-S2-08, INV-ARG-S2-13, INV-ARG-S2-10 |
| Credential Access | 서비스 credential, OTA 배포 토큰, signing workflow 권한 오용 | INV-STD-03, INV-STD-04, INV-ARG-S2-11, INV-ARG-S2-06 |
| Discovery | `argos-deploy`, `argos-signing`, OTA 서버, firmware catalog, device group 식별 | INV-ARG-S2-01, INV-ARG-S2-02, INV-ARG-08 |
| Privilege Escalation | 고객지원 포털·`argos-ops`·개발자·배포 계정으로 OTA 제어 권한 오용 | INV-STD-02, INV-ARG-S2-03, INV-ARG-S2-11 |
| Collection | OTA 대상 정보, firmware catalog, 배포 정책, rollout 상태 수집 | INV-ARG-08, INV-ARG-S2-07, INV-STD-10 |
| Command and Control | 정상 OTA 관리 기능과 내부 배포 경로를 오용해 배포 흐름 제어 | INV-ARG-S2-04, INV-ARG-S2-05, INV-ARG-S2-12 |
| Exfiltration | 승인 경로 밖 파일·서명·배포 상태가 OTA 신뢰 경계 안으로 유입되고 trace가 단절됨 | INV-ARG-S2-06, INV-ARG-S2-10, INV-STD-11 |
| Impact | 미승인 펌웨어 배포, 기기 신뢰성 훼손, tenant 서비스 신뢰성 저하, 사고 분석 지연 | INV-ARG-S2-05, INV-ARG-S2-09, INV-ARG-S2-10 |

---

# 13. 체인을 끊는 핵심 방어 지점

1. **외부 웹서비스 서버 측 실행 통제**
   - 차단 단계: Initial Access
   - 관련 불변식: INV-STD-CAND-WEB-01, INV-STD-CAND-WEB-02, INV-STD-CAND-WEB-03

2. **DMZ 내부망 직접 접근 차단**
   - 차단 단계: Discovery, Lateral Movement
   - 관련 불변식: INV-ARG-S2-01, INV-STD-08, INV-STD-14

3. **중요 계정 출처 기반 제한**
   - 차단 단계: Credential Access, Privilege Escalation
   - 관련 불변식: INV-ARG-S2-11, INV-STD-02

4. **고객지원 포털과 OTA 제어 권한 분리**
   - 차단 단계: Privilege Escalation
   - 관련 불변식: INV-ARG-S2-03

5. **내부 배포 경로 승인 파일 제한**
   - 차단 단계: Command and Control
   - 관련 불변식: INV-ARG-S2-04

6. **내부 배포 파일의 OTA 경로 유입 차단**
   - 차단 단계: Command and Control, Exfiltration
   - 관련 불변식: INV-ARG-S2-12

7. **펌웨어 서명키와 signing workflow 보호**
   - 차단 단계: Credential Access, Command and Control
   - 관련 불변식: INV-ARG-S2-02, INV-ARG-S2-06, INV-STD-03

8. **승인된 CI/CD 산출물·hash·서명 검증**
   - 차단 단계: Command and Control, Impact
   - 관련 불변식: INV-ARG-S2-05

9. **OTA 대상 tenant·device group 검증**
   - 차단 단계: Collection, Command and Control, Impact
   - 관련 불변식: INV-ARG-S2-07, INV-ARG-08

10. **고위험 OTA 정책 변경 승인 통제**
    - 차단 단계: Defense Evasion, Impact
    - 관련 불변식: INV-ARG-S2-08, INV-ARG-S2-13

11. **기기 측 서명·캠페인·rollback 검증**
    - 차단 단계: Impact
    - 관련 불변식: INV-ARG-S2-09

12. **OTA 전체 trace 연결과 로그 보존**
    - 차단 또는 피해 축소 단계: Exfiltration, Impact
    - 관련 불변식: INV-ARG-S2-10, INV-STD-10, INV-STD-11
