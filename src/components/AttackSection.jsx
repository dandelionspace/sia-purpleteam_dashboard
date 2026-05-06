import { useState } from "react";

// ── 상수 ────────────────────────────────────────────────────────────────────

// risk_level → 위험도 숫자 매핑
const RISK_SCORE = { critical: 95, high: 78, medium: 60, low: 35 };

// 단계 노드 색상 (순서대로 진해짐)
const NODE_COLORS = [
  { bg: "#E6F1FB", text: "#0C447C" },
  { bg: "#CCDFF7", text: "#0C447C" },
  { bg: "#185FA5", text: "#fff"    },
  { bg: "#0C447C", text: "#fff"    },
  { bg: "#042C53", text: "#fff"    },
];

const SEVERITY_COLOR = {
  Critical: "#E05252", High: "#F0874A", Medium: "#F6C142", Low: "#38A169",
};
const SEVERITY_BADGE = {
  Critical: { bg: "#FEF1F1", text: "#C53030" },
  High:     { bg: "#FEF4EE", text: "#BF5520" },
  Medium:   { bg: "#FEF9E4", text: "#9C6F00" },
  Low:      { bg: "#F0FDF9", text: "#276749" },
};
const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"];

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

const getSeverity = (tech, violationList) => {
  if (!tech.violation_ids?.length) return null;
  const linked = violationList.filter((v) => tech.violation_ids.includes(v.id));
  return SEVERITY_ORDER.find((s) => linked.some((v) => v.severity === s)) || null;
};

// ── MITRE 히트맵 ─────────────────────────────────────────────────────────────

function MitreHeatmap({ mitreMapping, violations }) {
  const [selected, setSelected] = useState(null);

  const tacticMap = Object.fromEntries((mitreMapping ?? []).map((t) => [t.tactic_id, t]));

  const handleClick = (tech, tacticName) => {
    if (selected?.technique_id === tech.technique_id && selected?.tactic_name === tacticName) {
      setSelected(null);
    } else {
      setSelected({ ...tech, tactic_name: tacticName });
    }
  };

  const linkedViolations = selected
    ? violations.filter((v) => selected.violation_ids?.includes(v.id))
    : [];

  return (
    <div style={card}>
      <p style={cardTitle}>MITRE ATT&CK 매트릭스 — 탐지된 전술/기법</p>

      <div style={{ overflowX: "auto", paddingBottom: 8 }}>
        <div style={{ minWidth: ALL_TACTICS.length * 92 }}>
          {/* 전술 헤더 */}
          <div style={{ display: "grid", gridTemplateColumns: `repeat(${ALL_TACTICS.length}, 1fr)`, gap: 4, marginBottom: 4 }}>
            {ALL_TACTICS.map((tac) => (
              <div key={tac.id} style={{ fontSize: 10, color: "#73726c", textAlign: "center", padding: "2px 0", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                {tac.name}
              </div>
            ))}
          </div>

          {/* 기법 칸 */}
          <div style={{ display: "grid", gridTemplateColumns: `repeat(${ALL_TACTICS.length}, 1fr)`, gap: 4 }}>
            {ALL_TACTICS.map((tac) => {
              const tacData    = tacticMap[tac.id];
              const techniques = (tacData?.techniques ?? []).filter(
                (t) => t.violation_ids?.some((vid) => violations.some((v) => v.id === vid))
              );
              return (
                <div key={tac.id} style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                  {techniques.map((tech) => {
                    const sev        = getSeverity(tech, violations);
                    const bg         = SEVERITY_COLOR[sev] || "#E6F1FB";
                    const txtColor   = sev ? "#fff" : "#0C447C";
                    const isSelected = selected?.technique_id === tech.technique_id && selected?.tactic_name === tac.name;
                    return (
                      <div
                        key={tech.technique_id}
                        onClick={() => handleClick(tech, tac.name)}
                        style={{
                          height: 36, borderRadius: 3, cursor: "pointer",
                          display: "flex", alignItems: "center", justifyContent: "center",
                          fontSize: 9, fontWeight: 500,
                          background: bg, color: txtColor,
                          outline: isSelected ? "2px solid #378ADD" : "none",
                          outlineOffset: 1,
                          opacity: selected && !isSelected ? 0.5 : 1,
                          transition: "opacity 0.15s",
                        }}
                      >
                        {tech.technique_id}
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
            <span style={{ width: 12, height: 12, borderRadius: 2, background: SEVERITY_COLOR[s], display: "inline-block" }} />
            {s}
          </span>
        ))}
      </div>

      {/* 선택된 기법 하단 패널 — OLD 스타일 (border + 헤더/바디 분리) */}
      {selected && (
        <div style={{ marginTop: 12, border: "0.5px solid #CBD5E1", borderRadius: 8, overflow: "hidden" }}>
          {/* 패널 헤더 */}
          <div style={{
            display: "flex", justifyContent: "space-between", alignItems: "center",
            padding: "10px 14px", background: "#F1F5F9",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 13, fontWeight: 600, color: "#1E293B" }}>{selected.technique_id}</span>
              <span style={{ fontSize: 12, color: "#475569" }}>{selected.name}</span>
              <span style={{ fontSize: 11, color: "#94A3B8" }}>· {selected.tactic_name}</span>
            </div>
            <button onClick={() => setSelected(null)} style={{ background: "none", border: "none", cursor: "pointer", fontSize: 14, color: "#94A3B8", padding: 0 }}>✕</button>
          </div>
          {/* 패널 바디 */}
          <div style={{ padding: "12px 14px", background: "#fff" }}>
            <p style={{ fontSize: 11, color: "#73726c", margin: "0 0 8px" }}>
              연결된 불변식 위반 항목 {linkedViolations.length}개
            </p>
            {linkedViolations.map((v) => {
              const sc = SEVERITY_BADGE[v.severity] || { bg: "#f1efea", text: "#73726c" };
              return (
                <div key={v.id} style={{
                  display: "flex", alignItems: "center", gap: 10,
                  padding: "8px 10px", marginBottom: 6,
                  background: "#fff", border: "0.5px solid rgba(0,0,0,0.08)",
                  borderRadius: 6, fontSize: 12,
                }}>
                  <span style={{ fontWeight: 500, color: "#1a1a18", minWidth: 76, flexShrink: 0 }}>{v.id}</span>
                  <span style={{ fontSize: 10, fontWeight: 500, padding: "2px 8px", borderRadius: 99, background: sc.bg, color: sc.text, flexShrink: 0 }}>
                    {v.severity}
                  </span>
                  <span style={{ color: "#444", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {v.summary || v.description}
                  </span>
                  <span style={{ color: "#73726c", flexShrink: 0 }}>{v.server_zone}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── 공격 흐름 탭 (mitre_attack_flow → kill_chain 스타일) ─────────────────────

function KillChainTab({ flow }) {
  if (!flow?.length) return <p style={emptyText}>공격 흐름 데이터가 없습니다.</p>;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
      {flow.map((item) => (
        <div key={item.order} style={{
          display: "flex", gap: 12, alignItems: "flex-start",
          padding: "14px 0", borderBottom: "0.5px solid rgba(0,0,0,0.06)",
        }}>
          {/* 왼쪽: 번호 + 전술명 */}
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 3, flexShrink: 0, width: 56 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: "#73726c" }}>{item.order}</span>
            <span style={{ fontSize: 9, color: "#73726c", textAlign: "center", lineHeight: 1.3, wordBreak: "keep-all" }}>
              {item.tactic}
            </span>
          </div>

          {/* 오른쪽: INV 뱃지 + 단계 제목 + 이유 */}
          <div style={{ flex: 1 }}>
            {item.related_invariants?.length > 0 && (
              <div style={{ display: "flex", gap: 4, marginBottom: 5, flexWrap: "wrap" }}>
                {item.related_invariants.map((inv) => (
                  <span key={inv} style={{ fontSize: 10, fontWeight: 500, color: "#185FA5", background: "#EEF4FD", padding: "1px 6px", borderRadius: 4 }}>
                    {inv}
                  </span>
                ))}
              </div>
            )}
            <p style={{ fontSize: 12, color: "#1a1a18", margin: "0 0 3px", fontWeight: 500 }}>{item.step}</p>
            {item.reason && (
              <p style={{ fontSize: 11, color: "#73726c", margin: 0, lineHeight: 1.55 }}>{item.reason}</p>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── 취약점 및 기법 탭 (related_invariants → violation 상세) ─────────────────

function TechniquesTab({ chain, violations }) {
  const invIds = chain.related_invariants ?? [];

  if (!invIds.length) return <p style={emptyText}>연결된 불변식 정보가 없습니다.</p>;

  // violations 맵으로 빠르게 조회 — ID가 있으면 상세 데이터, 없으면 ID만 표시 (silent drop 방지)
  const violationMap = Object.fromEntries(violations.map((v) => [v.id, v]));
  const display = invIds.map((id) => violationMap[id] ?? { id, severity: null, summary: "", type: "", attack_phase: "" });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {display.map((item) => {
        const sc = item.severity ? (SEVERITY_BADGE[item.severity] || {}) : { bg: "#f1efea", text: "#73726c" };
        return (
          <div key={item.id} style={{ border: "0.5px solid rgba(0,0,0,0.08)", borderRadius: 8, padding: "10px 12px", background: "#fafbfc" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, flexWrap: "wrap" }}>
              <span style={{ fontSize: 12, fontWeight: 600, color: "#0C447C", fontFamily: "monospace" }}>{item.id}</span>
              {item.severity && (
                <span style={{ fontSize: 10, fontWeight: 500, background: sc.bg, color: sc.text, padding: "1px 7px", borderRadius: 99 }}>{item.severity}</span>
              )}
              {item.type && (
                <span style={{ fontSize: 10, color: "#73726c", background: "#f1efea", padding: "1px 7px", borderRadius: 99 }}>{item.type}</span>
              )}
              {item.attack_phase && (
                <span style={{ fontSize: 10, color: "#378ADD", background: "#F0F6FE", padding: "1px 7px", borderRadius: 99, marginLeft: "auto" }}>{item.attack_phase}</span>
              )}
            </div>
            {(item.summary || item.description) && (
              <p style={{ fontSize: 12, color: "#444", lineHeight: 1.55, margin: 0 }}>{item.summary || item.description}</p>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── 상세 공격 절차 탭 (manual_validation_guide → 절차 목록) ─────────────────

function ProceduresTab({ guide }) {
  if (!guide?.steps?.length) return <p style={emptyText}>상세 절차 데이터가 없습니다.</p>;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {guide.steps.map((step, i) => (
        <div key={i} style={{ border: "0.5px solid rgba(0,0,0,0.08)", borderRadius: 8, overflow: "hidden" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", background: "#f5f7fa", borderBottom: "0.5px solid rgba(0,0,0,0.06)" }}>
            <span style={{
              width: 20, height: 20, borderRadius: "50%", background: "#0C447C",
              color: "#fff", fontSize: 10, fontWeight: 600,
              display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
            }}>
              {i + 1}
            </span>
            <span style={{ fontSize: 12, fontWeight: 500, color: "#1a1a18" }}>{step}</span>
          </div>
          {/* 성공 기준이 있으면 해당 인덱스 표시 */}
          {guide.success_criteria?.[i] && (
            <div style={{ padding: "8px 12px" }}>
              <div style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
                <span style={{ fontSize: 10, color: "#73726c", flexShrink: 0, marginTop: 1 }}>성공 기준</span>
                <span style={{ fontSize: 11, color: "#444", lineHeight: 1.5 }}>{guide.success_criteria[i]}</span>
              </div>
            </div>
          )}
        </div>
      ))}
      {/* 안전 경계 */}
      {guide.safety_boundary?.length > 0 && (
        <div style={{ background: "#FEF3C7", borderRadius: 8, padding: "10px 14px" }}>
          <p style={{ fontSize: 10, fontWeight: 600, color: "#92400E", margin: "0 0 6px", textTransform: "uppercase", letterSpacing: "0.05em" }}>안전 경계</p>
          {guide.safety_boundary.map((s, i) => (
            <p key={i} style={{ fontSize: 11, color: "#92400E", margin: "0 0 2px" }}>· {s}</p>
          ))}
        </div>
      )}
    </div>
  );
}

// ── 시나리오 카드 ────────────────────────────────────────────────────────────

const DETAIL_TABS = [
  { key: "kill_chain",  label: "공격 흐름"     },
  { key: "techniques",  label: "취약점 및 기법" },
  { key: "procedures",  label: "상세 공격 절차" },
];

function ScenarioCard({ chain, violations }) {
  const [open, setOpen] = useState(false);
  const [tab, setTab]   = useState("kill_chain");

  const riskKey   = (chain.risk_level || "medium").toLowerCase();
  const riskScore = RISK_SCORE[riskKey] ?? 60;
  const steps     = chain.attack_chain ?? [];

  return (
    <div style={card}>
      {/* 헤더 */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <p style={{ ...cardTitle, margin: 0 }}>
          {chain.chain_scenario_id} · {chain.title}
        </p>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0, marginLeft: 12 }}>
          <span style={{ fontSize: 11, fontWeight: 500, background: "#E6F1FB", color: "#0C447C", padding: "3px 10px", borderRadius: 99 }}>
            위험도 {riskScore}
          </span>
          <button
            onClick={() => setOpen((v) => !v)}
            style={{ background: "none", border: "0.5px solid rgba(0,0,0,0.15)", borderRadius: 6, cursor: "pointer", fontSize: 11, color: "#73726c", padding: "3px 10px" }}
          >
            상세 {open ? "▲" : "▼"}
          </button>
        </div>
      </div>

      {/* 가로 노드 흐름 (attack_chain 기반) */}
      <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", justifyContent: "center" }}>
        {steps.map((step, i) => {
          const c = i === steps.length - 1
            ? NODE_COLORS[NODE_COLORS.length - 1]
            : NODE_COLORS[Math.min(i, NODE_COLORS.length - 2)];
          const label = step.length > 10 ? step.slice(0, 9) + "…" : step;
          return (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 3 }}>
                <div style={{
                  background: c.bg, color: c.text,
                  padding: "6px 10px", borderRadius: 8,
                  fontSize: 11, fontWeight: 500,
                  minWidth: 80, textAlign: "center",
                }} title={step}>
                  {label}
                </div>
                <span style={{ fontSize: 10, color: "#73726c" }}>{i + 1}단계</span>
              </div>
              {i < steps.length - 1 && <span style={{ fontSize: 16, color: "#73726c" }}>→</span>}
            </div>
          );
        })}
      </div>

      {/* 아코디언 */}
      {open && (
        <div style={{ marginTop: 16, borderTop: "0.5px solid rgba(0,0,0,0.08)", paddingTop: 14 }}>
          <div style={{ display: "flex", gap: 4, marginBottom: 14 }}>
            {DETAIL_TABS.map((t) => (
              <button key={t.key} onClick={() => setTab(t.key)} style={{
                padding: "5px 14px", borderRadius: 6, fontSize: 12, fontWeight: 500,
                cursor: "pointer", border: "none",
                background: tab === t.key ? "#0C447C" : "#f1efea",
                color: tab === t.key ? "#fff" : "#73726c",
                transition: "background 0.15s",
              }}>
                {t.label}
              </button>
            ))}
          </div>
          {tab === "kill_chain"  && <KillChainTab flow={chain.mitre_attack_flow} />}
          {tab === "techniques"  && <TechniquesTab chain={chain} violations={violations} />}
          {tab === "procedures"  && <ProceduresTab guide={chain.manual_validation_guide} />}
        </div>
      )}
    </div>
  );
}

// ── 메인 섹션 ────────────────────────────────────────────────────────────────

export default function AttackSection({ attackChains, mitreMapping, violations, activeFilter }) {
  const chains = attackChains ?? [];
  const viols  = violations   ?? [];

  const filteredViolations = activeFilter && activeFilter !== "전체"
    ? viols.filter((v) => v.invariant_source === activeFilter)
    : viols;

  return (
    <div>
      <p style={sectionLabel}>AI 공격 시나리오 및 MITRE ATT&CK 매핑</p>

      <MitreHeatmap mitreMapping={mitreMapping ?? []} violations={filteredViolations} />

      {chains.length === 0 ? (
        <div style={{ ...card, textAlign: "center", padding: "32px 0" }}>
          <p style={{ fontSize: 13, color: "#73726c", margin: "0 0 6px" }}>아직 생성된 AI 2 공격 시나리오가 없습니다</p>
          <p style={{ fontSize: 11, color: "#b0aea8", margin: 0 }}>POST /api/ai2/scenarios 로 시나리오를 주입하면 여기에 표시됩니다</p>
        </div>
      ) : (
        chains.map((chain) => (
          <ScenarioCard key={chain.chain_scenario_id} chain={chain} violations={filteredViolations} />
        ))
      )}
    </div>
  );
}

const sectionLabel = { fontSize: 11, fontWeight: 500, color: "#73726c", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 10 };
const card         = { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: 16, marginBottom: 12 };
const cardTitle    = { fontSize: 13, fontWeight: 500, marginBottom: 12 };
const emptyText    = { fontSize: 12, color: "#b0aea8", textAlign: "center", padding: "20px 0", margin: 0 };
