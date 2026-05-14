import { useMemo, useState } from "react";
import { Badge, ChipList, SectionTitle } from "./common";

const CHAIN_BLUEPRINTS = {
  api_authorization: {
    title: "API 권한 경계 우회 검증",
    impact: "고객, 사용자, 영상, 기기 상세 정보가 소유자 또는 테넌트 검증 없이 반환될 수 있는지 확인합니다.",
    objective: "RedTeam은 테스트 계정과 테스트 리소스로 권한 서비스, 소유자 검증, 테넌트 검증이 실제 요청 경로에서 강제되는지 검증합니다.",
    exposedData: ["이름", "전화번호", "주소", "설치 위치", "영상 URL", "기기 상세"],
    steps: [
      {
        step_type: "actor_scope",
        title: "권한 주체와 토큰 범위 확인",
        description: "퇴사자 계정, 운영 계정, 서비스 계정이 어떤 역할과 테넌트 범위를 갖는지 확인합니다.",
        expected: "비활성 계정과 허용되지 않은 역할은 민감 API를 호출할 수 없어야 합니다.",
        check: "actor_id, role, account_status, token_tenant, MFA, 허용 네트워크 정보를 수집합니다.",
      },
      {
        step_type: "endpoint_reachability",
        title: "민감 API 엔드포인트 접근성 확인",
        description: "영상, 사용자, 기기 상세 API가 테스트 주체에게 도달 가능한지 확인합니다.",
        expected: "내부 API는 승인된 주체와 경로에서만 접근 가능해야 합니다.",
        check: "endpoint, method, route_type, source_ip, gateway trace, request_id를 확인합니다.",
      },
      {
        step_type: "authorization_boundary",
        title: "소유자·테넌트·중앙 권한 검증 확인",
        description: "요청 처리 중 owner check, tenant check, central authz service가 수행되는지 확인합니다.",
        expected: "검증 누락 또는 실패 시 authorization_decision은 deny여야 합니다.",
        check: "owner_check_performed, tenant_check_performed, authz_service_used, status_code를 비교합니다.",
      },
      {
        step_type: "resource_mismatch",
        title: "요청자 범위와 리소스 소유 범위 비교",
        description: "토큰의 테넌트와 리소스의 소유자·테넌트가 불일치할 때 접근이 차단되는지 확인합니다.",
        expected: "타 소유자 또는 타 테넌트 리소스는 403 또는 동등한 차단 결과가 나와야 합니다.",
        check: "token_tenant, resource_owner_id, resource_tenant_id, resource_id를 매칭합니다.",
      },
      {
        step_type: "sensitive_response",
        title: "민감 응답 필드 노출 확인",
        description: "성공 응답에 고객 위치, 연락처, 영상 URL 같은 민감 필드가 포함되는지 확인합니다.",
        expected: "권한 검증 전에는 민감 필드가 반환되지 않아야 합니다.",
        check: "response_fields, contains_pii, contains_address, contains_video_url을 확인합니다.",
      },
      {
        step_type: "audit_trace",
        title: "감사 로그와 탐지 흔적 확인",
        description: "허용·차단 결정이 audit, trace, SIEM evidence로 남는지 확인합니다.",
        expected: "모든 검증 요청은 request_id, trace_id, evidence_id로 추적 가능해야 합니다.",
        check: "audit_event_id, trace_id, request_id, evidence_ids를 연결합니다.",
      },
    ],
  },
  ota_firmware: {
    title: "OTA 펌웨어 배포 경계 검증",
    impact: "권한, 서명키, 펌웨어 카탈로그, OTA 정책 통제가 분리되어 있거나 누락되면 승인되지 않은 펌웨어가 배포 경로에 진입할 수 있습니다.",
    objective: "RedTeam은 테스트 펌웨어와 테스트 디바이스 그룹으로 서명, 등록, 정책 승인, 다운로드, 적용 단계가 같은 체인으로 통제되는지 검증합니다.",
    exposedData: ["펌웨어 해시", "서명키", "배포 정책", "디바이스 그룹", "적용 결과"],
    steps: [
      {
        step_type: "privileged_actor",
        title: "OTA/배포 권한 주체 확인",
        description: "운영 계정, 지원 계정, OTA 서비스가 배포·정책·서명 경로에 접근 가능한지 확인합니다.",
        expected: "지원/운영 계정은 승인된 작업 범위 밖의 OTA 변경을 수행할 수 없어야 합니다.",
        check: "actor_id, role, allowed_actions, source_asset, privileged_access_event를 확인합니다.",
      },
      {
        step_type: "signing_key_custody",
        title: "펌웨어 서명키 통제 확인",
        description: "서명키가 승인된 위치와 워크플로우에서만 사용되는지 확인합니다.",
        expected: "승인되지 않은 위치나 계정의 서명 요청은 차단되어야 합니다.",
        check: "signing_key_id, key_location, approved_location, signing_event_id, approver_id를 확인합니다.",
      },
      {
        step_type: "firmware_registration",
        title: "펌웨어 등록과 카탈로그 검증",
        description: "등록된 펌웨어의 해시, 파일 해시, 카탈로그 상태, 서명 검증 결과가 일치하는지 확인합니다.",
        expected: "카탈로그에 없거나 해시가 불일치하는 펌웨어는 등록 또는 배포가 거부되어야 합니다.",
        check: "firmware_id, firmware_hash, file_hash, catalog_status, signature_verification_result를 비교합니다.",
      },
      {
        step_type: "ota_policy",
        title: "OTA 정책 승인과 대상 범위 검증",
        description: "배포 정책이 승인되었는지, 대상 테넌트·모델·디바이스 그룹이 승인 범위 안인지 확인합니다.",
        expected: "승인 누락, 승인자 분리 위반, 대상 범위 초과는 배포 전에 차단되어야 합니다.",
        check: "deployment_id, approval_id, approver_id, campaign_approval_status, device_group, device_model을 확인합니다.",
      },
      {
        step_type: "device_apply",
        title: "디바이스 다운로드와 적용 결과 확인",
        description: "승인되지 않은 펌웨어나 서명 실패 펌웨어가 다운로드·적용 단계에서 차단되는지 확인합니다.",
        expected: "디바이스는 서명 실패 또는 범위 밖 펌웨어를 적용하지 않아야 합니다.",
        check: "device_id, download_result, apply_result, signature_check_result, firmware_version을 확인합니다.",
      },
      {
        step_type: "traceability",
        title: "배포 전 과정 상관관계 확인",
        description: "서명, 등록, 정책, 다운로드, 적용 로그가 같은 추적 키로 연결되는지 확인합니다.",
        expected: "모든 단계는 event_chain_id, deployment_id, firmware_hash, trace_id 중 하나 이상으로 연결되어야 합니다.",
        check: "event_chain_id, trace_id, deployment_id, firmware_hash, evidence_ids를 연결합니다.",
      },
    ],
  },
};

const FALLBACK_BLUEPRINT = {
  title: "침투 검증 후보",
  impact: "연결된 evidence와 불변식 위반을 기준으로 보안 경계가 실제로 강제되는지 확인해야 합니다.",
  objective: "RedTeam은 테스트 자산만 사용해 경계 조건, 차단 결과, 감사 추적 여부를 검증합니다.",
  exposedData: [],
  steps: [
    {
      step_type: "scope",
      title: "검증 범위 확인",
      description: "관련 계정, 엔드포인트, 자산, evidence 범위를 먼저 확정합니다.",
      expected: "검증 대상과 제외 대상이 명확히 분리되어야 합니다.",
      check: "risk_anchor, related_invariants, evidence_ids를 확인합니다.",
    },
    {
      step_type: "control",
      title: "보안 통제 강제 여부 확인",
      description: "접근 제어, 승인, 감사, 추적 통제가 실제 요청 경로에서 동작하는지 확인합니다.",
      expected: "정책 위반 조건에서는 허용 결과가 나오지 않아야 합니다.",
      check: "observed_controls, validation_focus, missing_fields를 확인합니다.",
    },
  ],
};

export default function PenetrationScenarioSection({
  attackChains = [],
  preventiveRiskChains = [],
  observedAttackChains = [],
  ai2ChainPayload = {},
  violations = [],
}) {
  const chains = useMemo(
    () => normalizeScenarioChains({ attackChains, preventiveRiskChains, observedAttackChains, ai2ChainPayload, violations }),
    [attackChains, preventiveRiskChains, observedAttackChains, ai2ChainPayload, violations]
  );
  const [selectedId, setSelectedId] = useState(chains[0]?.id ?? null);
  const selected = chains.find((chain) => chain.id === selectedId) ?? chains[0];

  const counts = useMemo(() => ({
    total: chains.length,
    observed: chains.filter((chain) => chain.status === "observed").length,
    preventive: chains.filter((chain) => chain.status !== "observed").length,
    ready: chains.filter((chain) => chain.ready).length,
  }), [chains]);

  if (!chains.length) {
    return (
      <section style={styles.section}>
        <SectionTitle title="침투 시나리오" subtitle="AI2 체인과 예방형 위험 경로를 RedTeam 검증 단계로 정리합니다." />
        <div style={styles.empty}>도출된 침투 시나리오가 없습니다.</div>
      </section>
    );
  }

  return (
    <section style={styles.section}>
      <SectionTitle
        title="침투 시나리오"
        subtitle="공격 성공 로그가 아니라 RedTeam이 검증해야 할 보안 경계, 단계, 판단 기준을 중심으로 정리한 화면입니다."
      />

      <div style={styles.kpiGrid}>
        <Metric label="전체 시나리오" value={counts.total} />
        <Metric label="관측 체인" value={counts.observed} />
        <Metric label="예방형 후보" value={counts.preventive} />
        <Metric label="검증 준비" value={counts.ready} />
      </div>

      <div style={styles.layout}>
        <div style={styles.listPanel}>
          {chains.map((chain, index) => (
            <button
              key={chain.id}
              type="button"
              onClick={() => setSelectedId(chain.id)}
              style={scenarioButton(selected?.id === chain.id)}
            >
              <span style={styles.scenarioIndex}>{index + 1}</span>
              <span style={styles.scenarioText}>
                <strong>{chain.displayTitle}</strong>
                <span>{chain.id}</span>
              </span>
              <span style={statusBadge(chain.status)}>{chain.statusLabel}</span>
            </button>
          ))}
        </div>

        {selected && <ScenarioDetail scenario={selected} />}
      </div>
    </section>
  );
}

function ScenarioDetail({ scenario }) {
  const anchor = scenario.riskAnchor ?? {};
  const variants = scenario.variants.slice(0, 6);

  return (
    <article style={styles.detailPanel}>
      <div style={styles.detailHeader}>
        <div style={{ minWidth: 0 }}>
          <div style={styles.metaRow}>
            <span style={statusBadge(scenario.status)}>{scenario.statusLabel}</span>
            <Badge value={capitalize(scenario.riskLevel)} />
            <span style={styles.familyBadge}>{scenario.familyLabel}</span>
          </div>
          <h3 style={styles.detailTitle}>{scenario.displayTitle}</h3>
          <p style={styles.detailSummary}>{scenario.impact}</p>
        </div>
      </div>

      <div style={styles.objectiveBox}>
        <strong>RedTeam 목표</strong>
        <p>{scenario.objective}</p>
      </div>

      <div style={styles.anchorGrid}>
        <InfoTile label="주체" value={anchor.actors} />
        <InfoTile label="엔드포인트" value={anchor.endpoints} />
        <InfoTile label="리소스" value={anchor.resource_ids} />
        <InfoTile label="배포 ID" value={anchor.deployment_ids} />
        <InfoTile label="펌웨어 해시" value={anchor.firmware_hashes} />
        <InfoTile label="대상 디바이스" value={anchor.device_ids} />
      </div>

      <div style={styles.stepsHeader}>
        <h4>공격 단계 및 검증 기준</h4>
        <span>{scenario.steps.length}단계</span>
      </div>
      <div style={styles.timeline}>
        {scenario.steps.map((step, index) => (
          <div key={`${scenario.id}-${step.step_type}-${index}`} style={styles.stepItem}>
            <div style={styles.stepNumber}>{index + 1}</div>
            <div style={styles.stepBody}>
              <div style={styles.stepTop}>
                <strong>{step.title}</strong>
                <span>{step.step_type}</span>
              </div>
              <p style={styles.stepDescription}>{step.description}</p>
              <div style={styles.criteriaGrid}>
                <Criteria label="정상 기대 동작" value={step.expected} />
                <Criteria label="검증 방법" value={step.check} />
                <Criteria label="성공 판단" value={step.successCriteria} />
                <Criteria label="실패 판단" value={step.failureCriteria} />
              </div>
            </div>
          </div>
        ))}
      </div>

      <div style={styles.bottomGrid}>
        <div style={styles.card}>
          <h4>관련 불변식</h4>
          <ChipList values={scenario.relatedInvariants} />
        </div>
        <div style={styles.card}>
          <h4>노출 또는 영향 데이터</h4>
          <ChipList values={scenario.exposedData} />
        </div>
        <div style={styles.card}>
          <h4>보강 필요 데이터</h4>
          <ChipList values={scenario.missingFields} />
        </div>
        <div style={styles.card}>
          <h4>근거 Evidence</h4>
          <ChipList values={scenario.evidenceIds} />
        </div>
      </div>

      {variants.length > 0 && (
        <div style={styles.variantPanel}>
          <div style={styles.stepsHeader}>
            <h4>대표 검증 후보 조합</h4>
            <span>{scenario.variants.length}개 중 {variants.length}개 표시</span>
          </div>
          <div style={styles.variantGrid}>
            {variants.map((variant) => (
              <div key={variant.variant_id ?? variant.title} style={styles.variantCard}>
                <strong>{variant.title ?? variant.variant_id}</strong>
                <VariantLine label="주체" value={variant.grouping_keys?.actor_id ?? findPathValue(variant, "actor")} />
                <VariantLine label="엔드포인트" value={variant.grouping_keys?.endpoint ?? findPathValue(variant, "endpoint")} />
                <VariantLine label="리소스" value={variant.grouping_keys?.resource_id ?? findPathValue(variant, "resource")} />
                <VariantLine label="배포" value={variant.grouping_keys?.deployment_id ?? findPathValue(variant, "deployment")} />
                <VariantLine label="디바이스" value={variant.grouping_keys?.device_id ?? findPathValue(variant, "device")} />
                <VariantLine label="응답 필드" value={variant.response_fields ?? variant.sensitive_response_fields} />
              </div>
            ))}
          </div>
        </div>
      )}
    </article>
  );
}

function normalizeScenarioChains({ attackChains, preventiveRiskChains, observedAttackChains, ai2ChainPayload, violations }) {
  const source = uniqueById([
    ...asArray(observedAttackChains).map((chain) => ({ ...chain, __status: "observed" })),
    ...asArray(preventiveRiskChains).map((chain) => ({ ...chain, __status: "preventive_only" })),
    ...asArray(ai2ChainPayload?.observed_chains).map((chain) => ({ ...chain, __status: "observed" })),
    ...asArray(ai2ChainPayload?.preventive_risk_chains).map((chain) => ({ ...chain, __status: "preventive_only" })),
    ...asArray(attackChains),
  ]);

  const violationMap = Object.fromEntries(violations.map((item) => [item.invariant_id ?? item.id, item]));

  return source.map((chain) => {
    const id = chain.chain_scenario_id ?? chain.chain_id ?? chain.scenario_id ?? chain.id;
    const family = chain.risk_anchor?.family ?? inferFamily(chain);
    const blueprint = CHAIN_BLUEPRINTS[family] ?? FALLBACK_BLUEPRINT;
    const relatedInvariants = unique(asArray(chain.related_invariants));
    const variants = asArray(chain.variants);
    const missingFields = unique([
      ...asArray(chain.missing_fields),
      ...variants.flatMap((variant) => asArray(variant.missing_fields)),
    ]);
    const status = chain.__status ?? inferStatus(chain);
    const evidenceIds = unique([
      ...asArray(chain.evidence_ids),
      ...variants.flatMap((variant) => asArray(variant.evidence_ids)),
      ...relatedInvariants.flatMap((invariantId) => asArray(violationMap[invariantId]?.evidence_ids)),
    ]);
    const displayTitle = safeTitle(chain.title, family) ?? blueprint.title;
    const steps = blueprint.steps.map((step) => ({
      ...step,
      successCriteria: successCriteriaFor(step.step_type),
      failureCriteria: failureCriteriaFor(step.step_type),
    }));

    return {
      raw: chain,
      id,
      family,
      familyLabel: family === "api_authorization" ? "API 권한" : family === "ota_firmware" ? "OTA 펌웨어" : "검증 후보",
      displayTitle,
      riskLevel: chain.risk_level ?? "medium",
      status,
      statusLabel: status === "observed" ? "관측 체인" : "예방형 검증 후보",
      ready: variants.length ? variants.some((variant) => variant.redteam_ready && !asArray(variant.missing_fields).length) : !missingFields.length,
      impact: blueprint.impact,
      objective: blueprint.objective,
      exposedData: unique([...blueprint.exposedData, ...variants.flatMap((variant) => asArray(variant.response_fields ?? variant.sensitive_response_fields))]),
      steps,
      variants,
      riskAnchor: chain.risk_anchor ?? {},
      relatedInvariants,
      evidenceIds,
      missingFields,
    };
  }).filter((chain) => chain.id);
}

function Metric({ label, value }) {
  return (
    <div style={styles.metricCard}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function InfoTile({ label, value }) {
  if (!hasValue(value)) return null;
  return (
    <div style={styles.infoTile}>
      <span>{label}</span>
      <strong>{formatList(value)}</strong>
    </div>
  );
}

function Criteria({ label, value }) {
  return (
    <div style={styles.criteria}>
      <span>{label}</span>
      <p>{value}</p>
    </div>
  );
}

function VariantLine({ label, value }) {
  if (!hasValue(value)) return null;
  return (
    <div style={styles.variantLine}>
      <span>{label}</span>
      <strong>{formatList(value)}</strong>
    </div>
  );
}

function successCriteriaFor(stepType) {
  if (stepType.includes("audit") || stepType.includes("trace")) return "차단 또는 허용 결과가 동일한 추적 키와 evidence로 재구성됩니다.";
  if (stepType.includes("response")) return "권한 검증 실패 조건에서 민감 필드가 반환되지 않습니다.";
  if (stepType.includes("device")) return "승인되지 않은 펌웨어가 디바이스에 적용되지 않습니다.";
  return "정책 위반 조건에서 요청이 차단되고 감사 흔적이 남습니다.";
}

function failureCriteriaFor(stepType) {
  if (stepType.includes("response")) return "검증 실패 조건에서도 고객·영상·위치 정보가 응답에 포함됩니다.";
  if (stepType.includes("trace")) return "단계별 로그가 같은 체인으로 연결되지 않아 재현과 감사가 어렵습니다.";
  if (stepType.includes("device")) return "승인되지 않은 펌웨어가 다운로드 또는 적용 단계까지 진행됩니다.";
  return "검증 누락 상태에서 allow, 200, applied 같은 성공 결과가 관측됩니다.";
}

function inferFamily(chain) {
  const text = [
    chain.chain_id,
    chain.chain_scenario_id,
    chain.title,
    chain.risk_anchor?.source_anchor_chain_id,
    ...asArray(chain.validation_focus),
  ].join(" ").toLowerCase();
  if (text.includes("ota") || text.includes("firmware") || text.includes("deployment") || text.includes("signing")) return "ota_firmware";
  if (text.includes("api") || text.includes("authorization") || text.includes("endpoint")) return "api_authorization";
  return "unknown";
}

function inferStatus(chain) {
  if (chain.chain_type?.includes?.("preventive") || asArray(chain.variants).length) return "preventive_only";
  return "observed";
}

function safeTitle(title, family) {
  const text = String(title ?? "").trim();
  if (!text || /[�怨꾩젙沅뚰븳]/.test(text)) return null;
  if (family === "api_authorization" && text.length < 8) return "API 권한 경계 우회 검증";
  if (family === "ota_firmware" && text.length < 8) return "OTA 펌웨어 배포 경계 검증";
  return text;
}

function findPathValue(variant, nodeType) {
  return asArray(variant.path).find((node) => node?.node_type === nodeType)?.value;
}

function uniqueById(chains) {
  const map = new Map();
  chains.forEach((chain) => {
    const id = chain?.chain_scenario_id ?? chain?.chain_id ?? chain?.scenario_id ?? chain?.id;
    if (!id) return;
    if (!map.has(id)) map.set(id, chain);
  });
  return [...map.values()];
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function asArray(value) {
  if (Array.isArray(value)) return value.filter((item) => item !== null && item !== undefined && item !== "");
  return value ? [value] : [];
}

function hasValue(value) {
  if (Array.isArray(value)) return value.length > 0;
  return value !== null && value !== undefined && value !== "";
}

function formatList(value) {
  const items = asArray(value);
  if (!items.length) return "-";
  const shown = items.slice(0, 3).join(", ");
  return items.length > 3 ? `${shown} +${items.length - 3}` : shown;
}

function capitalize(value) {
  return String(value ?? "medium").replace(/^\w/, (char) => char.toUpperCase());
}

const styles = {
  section: { marginBottom: 24 },
  empty: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 8, padding: 28, textAlign: "center", color: "#667085", fontSize: 12 },
  kpiGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, marginBottom: 12 },
  metricCard: { background: "#fff", border: "1px solid #e4e7ec", borderRadius: 8, padding: "14px 16px", display: "grid", gap: 8 },
  layout: { display: "grid", gridTemplateColumns: "minmax(260px, 360px) 1fr", gap: 12, alignItems: "start" },
  listPanel: { display: "grid", gap: 8 },
  scenarioIndex: { width: 24, height: 24, borderRadius: 6, background: "#EEF4FD", color: "#0C447C", display: "inline-flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 800, flexShrink: 0 },
  scenarioText: { display: "grid", gap: 4, minWidth: 0, flex: 1, textAlign: "left" },
  detailPanel: { background: "#fff", border: "1px solid #e4e7ec", borderRadius: 8, padding: 18, minWidth: 0 },
  detailHeader: { display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 12 },
  metaRow: { display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", marginBottom: 8 },
  detailTitle: { margin: "0 0 8px", fontSize: 16, lineHeight: 1.45, color: "#111827" },
  detailSummary: { margin: 0, fontSize: 12, lineHeight: 1.6, color: "#475467" },
  familyBadge: { borderRadius: 999, padding: "2px 8px", fontSize: 10, fontWeight: 700, background: "#EEF4FD", color: "#0C447C" },
  objectiveBox: { background: "#F8FAFC", border: "1px solid #e4e7ec", borderRadius: 8, padding: "12px 14px", marginBottom: 12 },
  anchorGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 8, marginBottom: 16 },
  infoTile: { background: "#fff", border: "1px solid #eef2f6", borderRadius: 8, padding: "9px 10px", display: "grid", gap: 4 },
  stepsHeader: { display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, margin: "8px 0 10px" },
  timeline: { display: "grid", gap: 10 },
  stepItem: { display: "grid", gridTemplateColumns: "32px 1fr", gap: 10, alignItems: "start" },
  stepNumber: { width: 28, height: 28, borderRadius: 999, background: "#0C447C", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 800 },
  stepBody: { border: "1px solid #e4e7ec", borderRadius: 8, padding: 12, background: "#fff" },
  stepTop: { display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, marginBottom: 6 },
  stepDescription: { margin: "0 0 10px", color: "#475467", fontSize: 12, lineHeight: 1.6 },
  criteriaGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 8 },
  criteria: { background: "#F8FAFC", borderRadius: 6, padding: "8px 10px" },
  bottomGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 10, marginTop: 16 },
  card: { border: "1px solid #e4e7ec", borderRadius: 8, padding: 12, background: "#fff" },
  variantPanel: { marginTop: 16 },
  variantGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 10 },
  variantCard: { border: "1px solid #e4e7ec", borderRadius: 8, padding: 12, background: "#F8FAFC", display: "grid", gap: 8, minWidth: 0 },
  variantLine: { display: "grid", gridTemplateColumns: "72px 1fr", gap: 8, fontSize: 11 },
};

styles.metricCard.span = {};
styles.objectiveBox.strong = {};

function scenarioButton(active) {
  return {
    width: "100%",
    display: "flex",
    alignItems: "flex-start",
    gap: 10,
    border: `1px solid ${active ? "#185FA5" : "#e4e7ec"}`,
    background: active ? "#F0F7FF" : "#fff",
    borderRadius: 8,
    padding: 12,
    cursor: "pointer",
    color: "#1f2937",
  };
}

function statusBadge(status) {
  const observed = status === "observed";
  return {
    display: "inline-flex",
    alignItems: "center",
    width: "fit-content",
    borderRadius: 999,
    padding: "2px 8px",
    fontSize: 10,
    fontWeight: 800,
    background: observed ? "#E7F6EF" : "#FEF3C7",
    color: observed ? "#116149" : "#92400E",
    whiteSpace: "nowrap",
  };
}
