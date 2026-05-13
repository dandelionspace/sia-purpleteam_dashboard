import { useState } from "react";
import { Badge, ChipList, SectionTitle } from "./common";
import { sourceMatches } from "../utils/invariantSource";
import { formatServerZone } from "../utils/zoneDisplay";

const NODE_COLORS = [
  { bg: "#EEF4F8", text: "#24425C" },
  { bg: "#EEF4F8", text: "#24425C" },
  { bg: "#EEF4F8", text: "#24425C" },
  { bg: "#EEF4F8", text: "#24425C" },
  { bg: "#EEF4F8", text: "#24425C" },
];

const ALL_TACTICS = [
  { id: "TA0043", name: "정찰" },
  { id: "TA0042", name: "리소스 개발" },
  { id: "TA0001", name: "초기 접근" },
  { id: "TA0002", name: "실행" },
  { id: "TA0003", name: "지속성" },
  { id: "TA0004", name: "권한 상승" },
  { id: "TA0005", name: "방어 우회" },
  { id: "TA0006", name: "자격증명 접근" },
  { id: "TA0007", name: "탐색" },
  { id: "TA0008", name: "내부 이동" },
  { id: "TA0009", name: "수집" },
  { id: "TA0011", name: "C2" },
  { id: "TA0010", name: "데이터 탈취" },
  { id: "TA0040", name: "영향" },
];

const TACTIC_NAME_MAP = Object.fromEntries(ALL_TACTICS.map((t) => [t.id, t.name]));

const SEVERITY_COLOR = { Critical: "#FEE2E2", High: "#FFEDD5", Medium: "#FEF9C3", Low: "#DCFCE7" };
const SEVERITY_TEXT  = { Critical: "#B91C1C", High: "#C2410C", Medium: "#A16207", Low: "#15803D" };
const SEVERITY_BADGE = {
  Critical: { bg: "#FEF1F1", text: "#C53030" },
  High:     { bg: "#FEF4EE", text: "#BF5520" },
  Medium:   { bg: "#FEF9E4", text: "#9C6F00" },
  Low:      { bg: "#F0FDF9", text: "#276749" },
};

function normalizeSev(sev) {
  if (!sev) return null;
  const cap = sev.charAt(0).toUpperCase() + sev.slice(1).toLowerCase();
  return SEVERITY_ORDER.includes(cap) ? cap : null;
}
const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"];

const DETAIL_TABS = [
  { key: "flow", label: "공격 흐름" },
  { key: "invariants", label: "취약점 및 기법" },
  { key: "evidence", label: "Evidence / 자산" },
];

export default function AttackSection({ attackChains = [], diagnosticRedteamCandidates = [], mitreTacticMap = {}, diagnosticMitreTacticMap = {}, violations = [], activeFilter = "all" }) {
  const filteredViolations = activeFilter === "all"
    ? violations
    : violations.filter((item) => sourceMatches(item.invariant_source ?? item.source, activeFilter));

  const officialMitreMissing = mitreTacticMap?.mapping_status === "missing_or_insufficient_evidence" || (mitreTacticMap?.active_tactic_count === 0 && !mitreTacticMap?.tactics?.some?.((t) => t.active));
  const effectiveMitreMap = officialMitreMissing ? diagnosticMitreTacticMap : mitreTacticMap;
  const mitreDiagnostic = officialMitreMissing && Object.keys(diagnosticMitreTacticMap).length > 0;

  return (
    <section>
      <MitreHeatmap violations={filteredViolations} mitreTacticMap={effectiveMitreMap} isDiagnostic={mitreDiagnostic} officialMissing={officialMitreMissing} />
      <SectionTitle title="공식 AI 공격 체인" subtitle="AI2가 공식으로 생성한 Red Team 시나리오 후보" />
      {attackChains.length ? (
        attackChains.map((chain, index) => (
          <ChainCard key={chain.chain_scenario_id} chain={chain} chainIndex={index + 1} violations={filteredViolations} />
        ))
      ) : (
        <div style={styles.card}>공식 AI2 공격 체인이 없습니다.</div>
      )}
    </section>
  );
}

// ── MITRE ATT&CK 히트맵 (구 버전 스타일) ────────────────────────────────────

function MitreHeatmap({ violations = [], mitreTacticMap = {}, isDiagnostic = false, officialMissing = false }) {
  const [selected, setSelected] = useState(null);

  const violationById = Object.fromEntries(
    violations.map((v) => [v.invariant_id ?? v.id, v])
  );

  // 1순위: violations[].mitre_tactic 필드로 매핑
  const tacticViolMap = {};
  const tacticTechMap = {};
  violations.forEach((v) => {
    const tactic = v.mitre_tactic;
    if (!tactic) return;
    if (!tacticViolMap[tactic]) tacticViolMap[tactic] = [];
    tacticViolMap[tactic].push(v);
    const tech = v.mitre_technique;
    if (tech) {
      if (!tacticTechMap[tactic]) tacticTechMap[tactic] = new Set();
      tacticTechMap[tactic].add(tech);
    }
  });

  // 2순위: mitreTacticMap.tactics[].violated_invariants 로 매핑
  (mitreTacticMap?.tactics ?? []).forEach((tactic) => {
    const tacticId = tactic.tactic_id;
    if (!tacticId) return;
    const invIds = asArray(tactic.violated_invariants ?? tactic.invariants).map(invariantRefId).filter(Boolean);
    if (!invIds.length) return;
    const linked = invIds.map((id) => violationById[id]).filter(Boolean);
    if (!linked.length) return;
    if (!tacticViolMap[tacticId]) tacticViolMap[tacticId] = [];
    linked.forEach((v) => {
      if (!tacticViolMap[tacticId].includes(v)) tacticViolMap[tacticId].push(v);
    });
  });

  const handleClick = (tac) => {
    if (selected?.tactic_id === tac.id) {
      setSelected(null);
    } else {
      setSelected({ tactic_id: tac.id, tactic_name: tac.name, linkedViolations: tacticViolMap[tac.id] ?? [] });
    }
  };

  return (
    <section style={{ marginBottom: 22 }}>
      <SectionTitle
        title={isDiagnostic ? "MITRE ATT&CK Map - 진단용 추정 매핑" : "MITRE ATT&CK Map - 탐지된 전술/기법"}
        subtitle={isDiagnostic ? "불변식 카테고리 기반 진단용 보조 매핑 (공식 매핑 아님)" : "공격 체인과 연결된 MITRE 전술 및 기법"}
      />
      {officialMissing && (
        <div style={styles.mitreNotice}>
          공식 MITRE 매핑 상태: <strong>missing_or_insufficient_evidence</strong> — evidence 부족으로 공식 매핑이 없습니다.
          {isDiagnostic ? " 아래는 불변식 카테고리 기반 진단용 추정 매핑입니다." : ""}
        </div>
      )}
      <div style={styles.card}>
        <div style={{ overflowX: "auto", paddingBottom: 8 }}>
          <div style={{ minWidth: ALL_TACTICS.length * 92 }}>
            {/* 전술 헤더 */}
            <div style={{ display: "grid", gridTemplateColumns: `repeat(${ALL_TACTICS.length}, 1fr)`, gap: 4, marginBottom: 4 }}>
              {ALL_TACTICS.map((tac) => {
                const isActive = Boolean(tacticViolMap[tac.id]?.length);
                return (
                  <button
                    key={tac.id}
                    onClick={() => isActive && handleClick(tac)}
                    title={tac.name}
                    style={{
                      fontSize: 10,
                      padding: "5px 2px",
                      borderRadius: 4,
                      cursor: isActive ? "pointer" : "default",
                      border: "none",
                      background: "transparent",
                      color: isActive ? "#1E293B" : "#94A3B8",
                      textAlign: "center",
                      fontWeight: isActive ? 600 : 400,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {tac.name}
                  </button>
                );
              })}
            </div>

            {/* 불변식 셀 */}
            <div style={{ display: "grid", gridTemplateColumns: `repeat(${ALL_TACTICS.length}, 1fr)`, gap: 4 }}>
              {ALL_TACTICS.map((tac) => {
                const violsForTac = tacticViolMap[tac.id] ?? [];
                return (
                  <div key={tac.id} style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                    {violsForTac.map((v) => {
                      const invId = v.invariant_id ?? v.id;
                      const sev = normalizeSev(v.severity);
                      return (
                        <div
                          key={invId}
                          onClick={() => handleClick(tac)}
                          title={`${invId}${v.summary ? ` — ${v.summary}` : ""}`}
                          style={{
                            height: 36, borderRadius: 3, cursor: "pointer",
                            display: "flex", alignItems: "center", justifyContent: "center",
                            fontSize: 9, fontWeight: 700, textAlign: "center",
                            padding: "0 2px",
                            background: SEVERITY_COLOR[sev] ?? "#E6F1FB",
                            color: SEVERITY_TEXT[sev] ?? "#0C447C",
                            outline: selected?.tactic_id === tac.id ? "2px solid #378ADD" : "none",
                            outlineOffset: 1,
                            opacity: selected && selected.tactic_id !== tac.id ? 0.5 : 1,
                            transition: "opacity 0.15s",
                            overflow: "hidden",
                            whiteSpace: "nowrap",
                            textOverflow: "ellipsis",
                          }}
                        >
                          {invId}
                        </div>
                      );
                    })}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* 범례 */}
        <div style={{ display: "flex", gap: 14, marginTop: 10 }}>
          {SEVERITY_ORDER.map((s) => (
            <span key={s} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "#73726c" }}>
              <span style={{ width: 12, height: 12, borderRadius: 2, background: SEVERITY_COLOR[s], border: `1px solid ${SEVERITY_TEXT[s]}`, display: "inline-block" }} />
              {s}
            </span>
          ))}
        </div>

        {/* 선택된 전술 패널 */}
        {selected && (
          <div style={{ marginTop: 12, border: "0.5px solid #CBD5E1", borderRadius: 8, overflow: "hidden" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", background: "#F1F5F9" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: "#1E293B" }}>{selected.tactic_id}</span>
                <span style={{ fontSize: 12, color: "#475569" }}>{selected.tactic_name}</span>
              </div>
              <button onClick={() => setSelected(null)} style={{ background: "none", border: "none", cursor: "pointer", fontSize: 14, color: "#94A3B8", padding: 0 }}>✕</button>
            </div>
            <div style={{ padding: "12px 14px", background: "#fff" }}>
              <p style={{ fontSize: 11, color: "#73726c", margin: "0 0 8px" }}>
                연결된 불변식 위반 항목 {selected.linkedViolations.length}개
              </p>
              {selected.linkedViolations.map((v) => {
                const sc = SEVERITY_BADGE[normalizeSev(v.severity)] ?? { bg: "#f1efea", text: "#73726c" };
                return (
                  <div key={v.invariant_id ?? v.id} style={{
                    display: "flex", alignItems: "center", gap: 10,
                    padding: "8px 10px", marginBottom: 6,
                    background: "#fff", border: "0.5px solid rgba(0,0,0,0.08)",
                    borderRadius: 6, fontSize: 12,
                  }}>
                    <span style={{ fontWeight: 500, color: "#1a1a18", minWidth: 90, flexShrink: 0 }}>{v.invariant_id ?? v.id}</span>
                    <span style={{ fontSize: 10, fontWeight: 500, padding: "2px 8px", borderRadius: 99, background: sc.bg, color: sc.text, flexShrink: 0 }}>
                      {v.severity}
                    </span>
                    <span style={{ color: "#444", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {v.summary ?? v.description}
                    </span>
                    {v.zone && <span style={{ color: "#73726c", flexShrink: 0, fontSize: 11 }}>{formatServerZone(v.zone)}</span>}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

// ── 공격 체인 카드 ───────────────────────────────────────────────────────────

function ChainCard({ chain, chainIndex, violations = [], isDiagnostic = false }) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState("flow");
  const steps = normalizeChainSteps(chain, violations);
  const riskScore = getExplicitRiskScore(chain);
  const title = chain.title ?? chain.executive_summary ?? "Untitled attack chain";

  return (
    <article style={isDiagnostic ? { ...styles.card, ...styles.cardDiagnostic } : styles.card}>
      <div style={styles.chainHeader}>
        <div style={{ minWidth: 0 }}>
          <h3 style={styles.chainTitle}>{chainIndex}. {title}</h3>
          <div style={styles.metaRow}>
            <span style={styles.chainId}>{chain.chain_scenario_id}</span>
            {isDiagnostic && <span style={styles.diagnosticBadge}>진단용</span>}
            {chain.risk_level && <Badge value={capitalize(chain.risk_level)} />}
            {riskScore !== null && <span style={styles.riskScore}>위험도 {riskScore}</span>}
            {chain.scenario_basis?.violation_reason && (
              <span style={styles.mitreBadge}>{chain.scenario_basis.violation_reason}</span>
            )}
          </div>
          <ChipList values={chain.related_invariants} />
          {chain.scenario_basis?.summary && (
            <p style={{ margin: "6px 0 0", fontSize: 11, color: "#667085", lineHeight: 1.5 }}>
              {chain.scenario_basis.summary}
            </p>
          )}
        </div>
        <button style={styles.smallButton} onClick={() => setOpen((value) => !value)}>
          {open ? "닫기" : "상세 보기"}
        </button>
      </div>

      <ChainFlow steps={steps} />

      {open && (
        <div style={styles.expandedPanel}>
          <div style={styles.tabRow}>
            {DETAIL_TABS.map((item) => (
              <button key={item.key} style={tabButton(tab === item.key)} onClick={() => setTab(item.key)}>
                {item.label}
              </button>
            ))}
          </div>
          {tab === "flow" && <KillChainList steps={steps} />}
          {tab === "invariants" && <InvariantList chain={chain} violations={violations} />}
          {tab === "evidence" && <EvidenceAssetList steps={steps} />}
        </div>
      )}
    </article>
  );
}

function ChainFlow({ steps = [] }) {
  if (!steps.length) return null;
  return (
    <div style={styles.flowRow}>
      {steps.map((step, index) => {
        const color = index === steps.length - 1
          ? NODE_COLORS[NODE_COLORS.length - 1]
          : NODE_COLORS[Math.min(index, NODE_COLORS.length - 2)];
        const label = flowNodeLabel(step);
        return (
          <div key={`${step.order}-${label}`} style={styles.flowItem}>
            <div style={{ ...styles.flowNode, background: color.bg, color: color.text }} title={stepTitle(step)}>
              {label}
            </div>
            <span style={styles.flowStep}>{index + 1}단계</span>
            {index < steps.length - 1 && <span style={styles.flowArrow}>→</span>}
          </div>
        );
      })}
    </div>
  );
}

function KillChainList({ steps = [] }) {
  if (!steps.length) return <p style={styles.emptyText}>공격 흐름 데이터가 없습니다.</p>;
  return (
    <div>
      {steps.map((step, index) => (
        <div key={`${step.order}-${stepTitle(step)}`} style={styles.killChainItem}>
          <div style={styles.killChainIndex}>
            <span>{index + 1}</span>
          </div>
          <div style={{ flex: 1 }}>
            <div style={styles.mitreMeta}>
              {formatTacticLabel(step) && <span style={styles.mitreBadge}>{formatTacticLabel(step)}</span>}
              {formatTechniqueLabel(step) && <span style={styles.mitreBadge}>{formatTechniqueLabel(step)}</span>}
              <ChipList values={step.related_invariants} />
            </div>
            <p style={styles.killChainFinding}>{stepTitle(step)}</p>
            {step.reason && !isMitreMetaNote(step.reason) && <p style={styles.killChainReason}>{step.reason}</p>}
          </div>
        </div>
      ))}
    </div>
  );
}

function InvariantList({ chain, violations = [] }) {
  const ids = asArray(chain.related_invariants);
  if (!ids.length) return <p style={styles.emptyText}>연결된 불변식 정보가 없습니다.</p>;

  const violationMap = Object.fromEntries(violations.map((item) => [item.invariant_id ?? item.id, item]));
  return (
    <div style={{ display: "grid", gap: 8 }}>
      {ids.map((id) => {
        const item = violationMap[id] ?? { invariant_id: id };
        return (
          <div key={id} style={styles.invariantCard}>
            <div style={styles.mitreMeta}>
              <strong style={styles.monoText}>{item.invariant_id ?? id}</strong>
              {item.severity && <Badge value={item.severity} />}
              {item.mitre_tactic && <span style={styles.mitreBadge}>{formatTacticName(item.mitre_tactic)}</span>}
              {item.mitre_technique && <span style={styles.mitreBadge}>{item.mitre_technique}</span>}
            </div>
            {(item.summary || item.description) && <p style={styles.killChainReason}>{item.summary || item.description}</p>}
          </div>
        );
      })}
    </div>
  );
}

function EvidenceAssetList({ steps = [] }) {
  if (!steps.length) return <p style={styles.emptyText}>Evidence / 자산 데이터가 없습니다.</p>;

  return (
    <div style={styles.evidenceGrid}>
      {steps.map((step, index) => (
        <div key={`${step.order}-${index}`} style={styles.evidenceCard}>
          <div style={styles.evidenceHeader}>
            <strong>{step.order}. {stepTitle(step)}</strong>
            <span>{formatTacticLabel(step) || formatTechniqueLabel(step)}</span>
          </div>
          <DetailLine label="Evidence" value={<ChipList values={step.evidence_ids} />} />
          <DetailLine label="관련 자산" value={<ChipList values={step.threatened_asset_ids} />} />
          <DetailLine label="관련 불변식" value={<ChipList values={step.related_invariants} />} />
          <DetailLine label="Reason" value={step.violation_point || step.reason} />
        </div>
      ))}
    </div>
  );
}

function normalizeChainSteps(chain, violations) {
  const flowSteps = asArray(chain.mitre_attack_flow);
  const attackSteps = asArray(chain.attack_chain);
  const rawSteps = asArray(chain.step_reports);
  const maxLength = Math.max(flowSteps.length, attackSteps.length, rawSteps.length);

  return Array.from({ length: maxLength }, (_, index) => {
    const flow = flowSteps[index] ?? {};
    const attackStep = attackSteps[index];
    const raw = rawSteps[index] ?? {};
    const order = flow.order ?? flow.flow_order ?? raw.order ?? raw.step_order ?? index + 1;
    const tactic = flow.tactic ?? raw.tactic ?? raw.tactic_id;
    const technique = flow.technique ?? raw.technique ?? raw.technique_id;
    const stepRelated = unique([
      ...asArray(flow.related_invariants),
      ...asArray(raw.related_invariants ?? raw.violation_ids ?? raw.violated_invariants),
    ]);
    const related = stepRelated.length ? stepRelated : asArray(chain.related_invariants);
    const linkedViolations = violations.filter((violation) => related.includes(violation.invariant_id ?? violation.id));
    const fallbackViolation = linkedViolations[index % Math.max(linkedViolations.length, 1)];
    const stepText = firstUsefulText(
      flow.step,
      raw.step,
      raw.finding,
      raw.violation_point,
      raw.title,
      raw.path,
      attackStep,
      raw.chain_transition,
      raw.reason,
      chain.scenario_basis?.summary,
      chain.testability_reason,
      fallbackViolation?.summary,
      fallbackViolation?.reason
    );

    return {
      order,
      tactic,
      tactic_name: flow.tactic_name ?? raw.tactic_name ?? TACTIC_NAME_MAP[tactic],
      technique,
      technique_name: flow.technique_name ?? raw.technique_name,
      step: stepText,
      violation_point: firstUsefulText(raw.violation_point, raw.finding),
      reason: firstUsefulText(raw.chain_transition, raw.transition_to_next, raw.reason, flow.reason, fallbackViolation?.reason),
      related_invariants: related,
      evidence_ids: unique([
        ...asArray(raw.evidence_ids ?? raw.evidence_refs ?? raw.matched_evidence_ids),
        ...linkedViolations.flatMap((violation) => asArray(violation.evidence_ids)),
      ]),
      threatened_asset_ids: unique([
        ...asArray(raw.threatened_asset_ids ?? raw.affected_asset_ids ?? raw.asset_ids ?? raw.target_asset_ids),
        ...linkedViolations.flatMap((violation) => asArray(violation.asset_ids ?? violation.affected_registry_asset_ids ?? violation.affected_asset_ids)),
      ]),
    };
  });
}

function DetailLine({ label, value }) {
  if (!value) return null;
  return (
    <div style={styles.detailLine}>
      <span>{label}</span>
      <div>{value}</div>
    </div>
  );
}

function flowNodeLabel(step) {
  if (step.tactic) return formatTacticName(step.tactic, step.tactic_name);
  if (step.technique) return formatTechniqueLabel(step);
  return `단계 ${step.order}`;
}

function stepTitle(step) {
  const title = firstUsefulText(step.step, formatTechniqueLabel(step), formatTacticLabel(step));
  return stripLeadingStepNumber(title) || "공격 흐름 정보 없음";
}

function stripLeadingStepNumber(value) {
  return value ? String(value).replace(/^\s*\d+(?:\.\d+)*[.)]\s*/, "") : "";
}

function formatTacticLabel(step) {
  if (!step.tactic && !step.tactic_name) return "";
  return formatTacticName(step.tactic, step.tactic_name);
}

function formatTacticName(tactic, name) {
  const resolved = name ?? TACTIC_NAME_MAP[tactic];
  return [tactic, resolved].filter(Boolean).join(" - ");
}

function formatTechniqueLabel(step) {
  if (!step.technique && !step.technique_name) return "";
  return [step.technique, step.technique_name].filter(Boolean).join(" - ");
}

function getExplicitRiskScore(chain) {
  const value = chain.risk_score ?? chain.riskScore ?? chain.score;
  if (value === null || value === undefined || value === "") return null;
  const score = Number(value);
  return Number.isFinite(score) ? score : null;
}

function isMitreMetaNote(text) {
  if (!text) return false;
  const t = String(text).toLowerCase();
  return t.includes("mitre는 체인") || t.includes("보조 라벨") || t.startsWith("mitre is ");
}

function firstUsefulText(...values) {
  return values.find((value) => {
    if (value === null || value === undefined) return false;
    const text = String(value).trim();
    if (!text) return false;
    if (text === "No finding provided." || text === "Evidence correlation step") return false;
    return !/^chain-.+-step-\d+$/i.test(text);
  });
}

function asArray(value) {
  if (Array.isArray(value)) return value.filter((item) => item !== null && item !== undefined && item !== "");
  return value ? [value] : [];
}

function invariantRefId(value) {
  if (!value) return null;
  if (typeof value === "string") return value;
  return value.invariant_id ?? value.id ?? value.result_id ?? null;
}

function unique(values) {
  return [...new Set(asArray(values))];
}

function capitalize(value) {
  return String(value).replace(/^\w/, (char) => char.toUpperCase());
}

const styles = {
  card: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: 18, marginBottom: 12 },
  cardDiagnostic: { background: "#FFFBEB", border: "0.5px solid #FDE68A" },
  diagnosticBadge: { fontSize: 10, fontWeight: 700, color: "#92400E", background: "#FEF3C7", padding: "2px 7px", borderRadius: 5 },
  diagnosticNotice: { background: "#FEF3C7", border: "0.5px solid #FDE68A", borderRadius: 8, padding: "10px 14px", fontSize: 12, color: "#92400E", marginBottom: 12 },
  mitreNotice: { background: "#F1F5F9", border: "0.5px solid #CBD5E1", borderRadius: 8, padding: "10px 14px", fontSize: 12, color: "#475569", marginBottom: 8 },
  chainHeader: { display: "flex", justifyContent: "space-between", gap: 16, alignItems: "flex-start", marginBottom: 14 },
  chainTitle: { margin: "0 0 8px", fontSize: 14, color: "#1a1a18", lineHeight: 1.45 },
  metaRow: { display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 6 },
  chainId: { fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace", fontSize: 11, color: "#0b2f57", overflowWrap: "anywhere" },
  smallButton: { border: "0.5px solid rgba(0,0,0,0.12)", background: "#fff", color: "#73726c", borderRadius: 8, padding: "6px 10px", cursor: "pointer", fontSize: 12 },
  riskScore: { fontSize: 11, fontWeight: 700, background: "#E6F1FB", color: "#0C447C", padding: "3px 10px", borderRadius: 999 },
  flowRow: { display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", justifyContent: "flex-start", margin: "12px 0 6px" },
  flowItem: { display: "flex", alignItems: "center", gap: 6 },
  flowNode: { padding: "8px 12px", borderRadius: 8, fontSize: 11, fontWeight: 700, minWidth: 110, maxWidth: 170, minHeight: 34, display: "flex", alignItems: "center", justifyContent: "center", textAlign: "center", lineHeight: 1.25, border: "0.5px solid #DCE6EE" },
  flowStep: { display: "none" },
  flowArrow: { fontSize: 16, color: "#B7C3CE" },
  expandedPanel: { marginTop: 16, borderTop: "0.5px solid rgba(0,0,0,0.08)", paddingTop: 14 },
  tabRow: { display: "flex", gap: 4, marginBottom: 14 },
  killChainItem: { display: "flex", gap: 12, alignItems: "flex-start", padding: "14px 0", borderBottom: "0.5px solid rgba(0,0,0,0.06)" },
  killChainIndex: { display: "flex", flexDirection: "column", alignItems: "center", gap: 3, flexShrink: 0, width: 64, color: "#73726c", fontSize: 12, fontWeight: 700 },
  mitreMeta: { display: "flex", gap: 5, alignItems: "center", flexWrap: "wrap", marginBottom: 5 },
  mitreBadge: { fontSize: 10, fontWeight: 700, color: "#0C447C", background: "#EEF4FD", padding: "2px 7px", borderRadius: 5 },
  killChainFinding: { fontSize: 12, color: "#1a1a18", margin: "0 0 3px", fontWeight: 700, lineHeight: 1.55 },
  killChainReason: { fontSize: 11, color: "#73726c", margin: 0, lineHeight: 1.55 },
  invariantCard: { border: "0.5px solid rgba(0,0,0,0.08)", borderRadius: 8, padding: "10px 12px", background: "#FAFBFC" },
  monoText: { fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace", color: "#0C447C", fontSize: 12 },
  evidenceGrid: { display: "grid", gap: 10 },
  evidenceCard: { border: "0.5px solid rgba(0,0,0,0.08)", background: "#F8FAFC", borderRadius: 10, padding: 14 },
  evidenceHeader: { display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 10, color: "#185FA5", fontSize: 13, alignItems: "flex-start" },
  detailLine: { display: "grid", gridTemplateColumns: "150px 1fr", gap: 12, padding: "8px 12px", borderTop: "0.5px solid rgba(0,0,0,0.08)", fontSize: 12, color: "#1a1a18" },
  emptyText: { fontSize: 12, color: "#98a2b3", textAlign: "center", padding: "20px 0", margin: 0 },
};

function tabButton(active) {
  return {
    padding: "6px 14px",
    borderRadius: 6,
    fontSize: 12,
    fontWeight: 700,
    cursor: "pointer",
    border: "none",
    background: active ? "#0C447C" : "#F1F0EC",
    color: active ? "#FFFFFF" : "#73726c",
  };
}
