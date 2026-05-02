/*
 * AttackSection.jsx
 * 대시보드의 "AI 공격 시나리오 및 MITRE ATT&CK 매핑" 섹션을 담당하는 컴포넌트
 * - MITRE ATT&CK 매트릭스 히트맵과 공격 시나리오 카드로 구성됨
 * - MITRE 매핑은 탐지된 전술/기법을 시각화하며, 클릭 시 연결된 불변식 위반 항목을 보여줌
 * - 공격 시나리오 카드는 각 공격 체인의 단계별 노드를 표시
 * - 대시보드의 필터링 상태에 따라 표시되는 위반 항목이 달라짐
 */

import { useState } from "react";

const PHASE_STYLE = {
  초기침투:  { bg: "#E6F1FB", text: "#0C447C" },
  내부이동:  { bg: "#EEF4FD", text: "#185FA5" },
  권한상승:  { bg: "#EEEDFE", text: "#3C3489" },
  데이터탈취: { bg: "#E6F1FB", text: "#0C447C" },
  최종목표:  { bg: "#0C447C", text: "#E6F1FB" },
};

const SEVERITY_COLOR = {
  Critical: "#0C447C",
  High:     "#185FA5",
  Medium:   "#378ADD",
  Low:      "#85B7EB",
};

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"];

/* 기술과 연결된 위반 항목들을 분석하여 기술의 위험도를 결정하는 함수
 * - 연결된 위반 항목 중 가장 높은 위험도를 기술의 위험도로 간주
 * - 위험도 순서는 Critical > High > Medium > Low
 * - 연결된 위반 항목이 없는 경우 null 반환
 * - 이 함수는 MITRE 매핑에서 각 기술 칸의 색상을 결정하는 데 사용됨
 * - 예시: 기술 A가 Critical 2개, High 1개와 연결되어 있다면 기술 A의 위험도는 Critical이 됨
 * - viloation_ids 는 실제 불변식 위한 항복의 배열로 가정, 실제 데이터에서는 기술 객체에 violation_ids 배열이 포함되어 있다고 가정
 * - find 함수는 SEVERITY_ORDER 배열을 순환하며 조건을 만족하는 첫 번째 위험도를 반환한다. 
 */
const getSeverity = (tech, violationList) => {
  if (!tech.violation_ids || tech.violation_ids.length === 0) return null;
  const linked = violationList.filter((v) => tech.violation_ids.includes(v.id));
  return SEVERITY_ORDER.find((s) => linked.some((v) => v.severity === s)) || null;
};

const SEVERITY_BADGE = {
  Critical: { bg: "#E6F1FB", text: "#0C447C" },
  High:     { bg: "#EEF4FD", text: "#185FA5" },
  Medium:   { bg: "#F0F6FE", text: "#378ADD" },
  Low:      { bg: "#E1F5EE", text: "#085041" },
};

/* 공격 시나리오 상세 탭 */
const DETAIL_TABS = [
  { key: "kill_chain", label: "공격 흐름" },
  { key: "techniques", label: "취약점 및 기법" },
  { key: "procedures", label: "상세 공격 절차" },
];

/* 공격 시나리오 - [공격 흐름] 탭 컴포넌트 */
function KillChainTab({ items }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {items.map((item) => {
        const s = PHASE_STYLE[item.phase] || { bg: "#f1efea", text: "#444" };
        return (
          <div key={item.step} style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4, flexShrink: 0 , width: 52 }}>
              <span style={{ width: 22, height: 22, borderRadius: "50%", background: "transparent", color: "#73726c", fontSize: 11, fontWeight: 600, display: "flex", alignItems: "center", justifyContent: "center"  }}>
                {item.step}
              </span>
              <span style={{ fontSize: 9, background: "transparent", color: "#73726c", padding: "2px 6px", borderRadius: 99, fontWeight: 500, whiteSpace: "nowrap" }}>
                {item.phase}
              </span>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 3 }}>
                {item.violation_id && (
                  <span style={{ fontSize: 10, fontWeight: 500, color: "#185FA5", background: "#EEF4FD", padding: "1px 6px", borderRadius: 4 }}>
                    {item.violation_id}
                  </span>
                )}
                <span style={{ fontSize: 10, color: "#73726c", background: "#f5f7fa", padding: "1px 6px", borderRadius: 4 }}>
                  {item.mitre}
                </span>
              </div>
              <p style={{ fontSize: 12, color: "#333", lineHeight: 1.55, margin: 0 }}>{item.description}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* 공격 시나리오 - [취약점 및 기법] 탭 컴포넌트 */
function TechniquesTab({ items }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {items.map((item) => (
        <div key={item.id} style={{ border: "0.5px solid rgba(0,0,0,0.08)", borderRadius: 8, padding: "10px 12px", background: "#fafbfc" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5, flexWrap: "wrap" }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: "#0C447C" }}>{item.id}</span>
            <span style={{ fontSize: 12, fontWeight: 500, color: "#1a1a18" }}>{item.name}</span>
            <span style={{ fontSize: 10, color: "#73726c", background: "#f1efea", padding: "1px 7px", borderRadius: 99 }}>
              {item.tactic}
            </span>
            {item.violation_id && (
              <span style={{ fontSize: 10, fontWeight: 500, color: "#185FA5", background: "#EEF4FD", padding: "1px 6px", borderRadius: 4 }}>
                {item.violation_id}
              </span>
            )}
            <span style={{ fontSize: 10, color: "#378ADD", background: "#F0F6FE", padding: "1px 7px", borderRadius: 99, marginLeft: "auto" }}>
              {item.tool}
            </span>
          </div>
          <p style={{ fontSize: 12, color: "#444", lineHeight: 1.55, margin: 0 }}>{item.description}</p>
        </div>
      ))}
    </div>
  );
}

/* 공격 시나리오 - [상세 공격 절차] 탭 컴포넌트 */
function ProceduresTab({ items }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {items.map((item) => (
        <div key={item.step} style={{ border: "0.5px solid rgba(0,0,0,0.08)", borderRadius: 8, overflow: "hidden" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", background: "#f5f7fa", borderBottom: "0.5px solid rgba(0,0,0,0.06)" }}>
            <span style={{ width: 20, height: 20, borderRadius: "50%", background: "#0C447C", color: "#fff", fontSize: 10, fontWeight: 600, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
              {item.step}
            </span>
            <span style={{ fontSize: 12, fontWeight: 500, color: "#1a1a18", flex: 1 }}>{item.title}</span>
            <span style={{ fontSize: 10, color: "#378ADD", background: "#F0F6FE", padding: "2px 8px", borderRadius: 99, flexShrink: 0 }}>
              {item.tool}
            </span>
          </div>
          <div style={{ padding: "10px 12px" }}>
            <pre style={{ margin: "0 0 8px", padding: "8px 10px", background: "#1a1a18", color: "#a8d8a8", fontSize: 11, borderRadius: 6, overflowX: "auto", lineHeight: 1.6, fontFamily: "monospace" }}>
              {item.command}
            </pre>
            <div style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
              <span style={{ fontSize: 10, color: "#73726c", flexShrink: 0, marginTop: 1 }}>예상 결과</span>
              <span style={{ fontSize: 11, color: "#444", lineHeight: 1.5 }}>{item.expected}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

/* 공격 시나리오 및 MITRE 매핑 섹션의 메인 컴포넌트 */
function AttackChain({ chain }) {
  const [isOpen, setIsOpen] = useState(false);
  const [activeTab, setActiveTab] = useState("kill_chain");
  const hasDetail = chain.kill_chain || chain.techniques || chain.procedures;

  return (
    <div style={card}>
      {/* 카드 헤더 : 공격 시나리오 id와 제목 */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <p style={cardTitle}>{chain.chain_id} · {chain.title}</p>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 11, fontWeight: 500, background: "#E6F1FB", color: "#0C447C", padding: "3px 10px", borderRadius: 99 }}>
            위험도 {chain.risk_score}
          </span>
          {hasDetail && (
            <button
              onClick={() => setIsOpen((v) => !v)}
              style={{ background: "none", border: "0.5px solid rgba(0,0,0,0.15)", borderRadius: 6, cursor: "pointer", fontSize: 11, color: "#73726c", padding: "3px 10px", display: "flex", alignItems: "center", gap: 4 }}
            >
              상세 {isOpen ? "▲" : "▼"}
            </button>
          )}
        </div>
      </div>

      {/* 공격 흐름 노드 */}
      <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", justifyContent: "center" }}>
        {chain.nodes.map((node, i) => {
          const s = PHASE_STYLE[node.phase] || { bg: "#f1efea", text: "#444" };
          return (
            <div key={node.id} style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
                <div style={{ background: s.bg, color: s.text, padding: "6px 10px", borderRadius: 8, fontSize: 11, fontWeight: 500, minWidth: 80, textAlign: "center" }}>
                  {node.label}
                </div>
                {node.violation_id && (
                  <span style={{ fontSize: 10, color: "#73726c" }}>{node.violation_id}</span>
                )}
              </div>
              {i < chain.nodes.length - 1 && (
                <span style={{ fontSize: 16, color: "#73726c" }}>→</span>
              )}
            </div>
          );
        })}
      </div>

      {/* 아코디언 상세 패널 */}
      {isOpen && hasDetail && (
        <div style={{ marginTop: 16, borderTop: "0.5px solid rgba(0,0,0,0.08)", paddingTop: 14 }}>
          {/* 탭 헤더 (탭 버튼 만들기) */}
          <div style={{ display: "flex", gap: 4, marginBottom: 14 }}>
            {DETAIL_TABS.map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                style={{
                  padding: "5px 14px", borderRadius: 6, fontSize: 12, fontWeight: 500, cursor: "pointer", border: "none",
                  background: activeTab === tab.key ? "#0C447C" : "#f1efea",
                  color: activeTab === tab.key ? "#fff" : "#73726c",
                  transition: "background 0.15s",
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* 탭 콘텐츠 */}
          {activeTab === "kill_chain" && chain.kill_chain && <KillChainTab items={chain.kill_chain} />}
          {activeTab === "techniques" && chain.techniques && <TechniquesTab items={chain.techniques} />}
          {activeTab === "procedures" && chain.procedures && <ProceduresTab items={chain.procedures} />}
        </div>
      )}
    </div>
  );
}

/* MITRE ATT&CK 매트릭스 히트맵 컴포넌트
 *
 * - mitreMapping: 전술과 기법이 포함된 MITRE 매핑 데이터
 * - violations: 현재 대시보드에서 필터링된 불변식 위반 항목 목록
 * - 각 기법 칸은 연결된 위반 항목들의 위험도를 기반으로 색상이 결정됨
 * - 칸을 클릭하면 해당 기법과 연결된 위반 항목들이 아래 패널에 표시됨
 * - 예시: 초기침투 전술의 Tactic 1 기법 칸은 Critical과 High 위반 항목이 연결되어 있어 가장 높은 위험도인 Critical 색상으로 표시됨. 사용자가 이 칸을 클릭하면 Tactic 1과 연결된 모든 위반 항목이 아래 패널에 리스트업됨
 */
function MitreHeatmap({ mitreMapping, violations }) {
  const [selected, setSelected] = useState(null); // 선택된 기법 정보를 상태로 관리 (technique_id, name, tactic_name, violation_ids 등)
  
  /* 기법 칸 클릭 시 호출되는 함수 */
  const handleClick = (tech, tactic) => {
    if (selected && selected.technique_id === tech.technique_id) { // 이미 선택된 칸을 다시 클릭하면 선택 해제
      setSelected(null);
    } else {
      setSelected({ ...tech, tactic_name: tactic.tactic_name });
    }
  };
  
  /* 선택된 기법과 연결된 위반 항목들의 정보를 불러옴 */
  const linkedViolations = selected
    ? violations.filter((v) => selected.violation_ids.includes(v.id))
    : [];

  return (
    <div style={card}>
      <p style={cardTitle}>MITRE ATT&CK 매트릭스 — 탐지된 전술/기법</p>

      {/* 히트맵 */}
      <div style={{ overflowX: "auto", paddingBottom: 8 }}>
        <div style={{ minWidth: 900 }}>
          {/* 전술 헤더 */}
          <div style={{ display: "grid", gridTemplateColumns: `repeat(${mitreMapping.length}, 1fr)`, gap: 4, marginBottom: 4 }}>
            {mitreMapping.map((tactic) => (
              <div key={tactic.tactic_id} style={{ fontSize: 10, color: "#73726c", textAlign: "center", padding: "2px 0" }}>
                {tactic.tactic_name}
              </div>
            ))}
          </div>

          {/* 기법 칸 */}
          <div style={{ display: "grid", gridTemplateColumns: `repeat(${mitreMapping.length}, 1fr)`, gap: 4 }}>
            {mitreMapping.map((tactic) => (
              <div key={tactic.tactic_id} style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                {tactic.techniques
                  .filter((tech) => tech.violation_ids && violations.some((v) => tech.violation_ids.includes(v.id)))
                  .map((tech) => {
                  const isSelected = selected && selected.technique_id === tech.technique_id && selected.tactic_name === tactic.tactic_name;
                  const hasViolation = tech.violation_ids && tech.violation_ids.length > 0;
                  const severity = getSeverity(tech, violations);
                  const bgColor = SEVERITY_COLOR[severity] || "#E6F1FB";
                  const textColor = severity === "Critical" || severity === "High" ? "#E6F1FB" : "#0C447C";
                  return (
                    <div
                      key={tech.technique_id}
                      onClick={() => handleClick(tech, tactic)}
                      style={{
                        position: "relative",
                        height: 36, borderRadius: 3,
                        background: bgColor,
                        display: "flex", alignItems: "center", justifyContent: "center",
                        fontSize: 9, fontWeight: 500,
                        color: textColor,
                        cursor: "pointer",
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
            ))}
          </div>
        </div>
      </div>

      {/* 범례 : 각 색깔이 뭘 의미하는지 설명 */}
      <div style={{ display: "flex", gap: 12, marginTop: 10, fontSize: 11, color: "#73726c", flexWrap: "wrap" }}>
        {[["Critical", "#0C447C"], ["High", "#185FA5"], ["Medium", "#378ADD"], ["Low", "#85B7EB"]].map(([label, color]) => (
          <span key={label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: color, display: "inline-block" }} />
            {label}
          </span>
        ))}
      </div>

      {/* 클릭 드릴다운 패널 */}
      {selected && (
        <div style={{
          marginTop: 12, border: "0.5px solid #378ADD",
          borderRadius: 8, overflow: "hidden",
        }}>
          {/* 패널 헤더 */}
          <div style={{
            display: "flex", justifyContent: "space-between", alignItems: "center",
            padding: "10px 14px", background: "#E6F1FB",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 13, fontWeight: 500, color: "#0C447C" }}>
                {selected.technique_id}
              </span>
              <span style={{ fontSize: 12, color: "#185FA5" }}>{selected.name}</span>
              <span style={{ fontSize: 11, color: "#73726c" }}>· {selected.tactic_name}</span>
            </div>
            <button
              onClick={() => setSelected(null)}
              style={{ background: "none", border: "none", cursor: "pointer", fontSize: 14, color: "#73726c" }}
            >
              ✕
            </button>
          </div>

          {/* 연결된 위반 항목 */}
          <div style={{ padding: "12px 14px" }}>
            {linkedViolations.length > 0 ? (
              <>
                <p style={{ fontSize: 11, color: "#73726c", marginBottom: 8 }}>
                  연결된 불변식 위반 항목 {linkedViolations.length}개
                </p>
                {linkedViolations.map((v) => {
                  const sc = SEVERITY_BADGE[v.severity] || {};
                  return (
                    <div key={v.id} style={{
                      display: "flex", alignItems: "center", gap: 10,
                      padding: "8px 10px", marginBottom: 6,
                      background: "#fff", border: "0.5px solid rgba(0,0,0,0.08)",
                      borderRadius: 6, fontSize: 12,
                    }}>
                      <span style={{ fontWeight: 500, color: "#1a1a18", minWidth: 64 }}>{v.id}</span>
                      <span style={{
                        fontSize: 10, fontWeight: 500, padding: "2px 8px", borderRadius: 99,
                        background: sc.bg, color: sc.text, flexShrink: 0,
                      }}>
                        {v.severity}
                      </span>
                      <span style={{ color: "#444", flex: 1 }}>{v.description}</span>
                      <span style={{ color: "#73726c", flexShrink: 0 }}>{v.server_zone}</span>
                    </div>
                  );
                })}
              </>
            ) : (
              <p style={{ fontSize: 12, color: "#b0b0b0" }}>
                현재 스캔에서 이 기법과 연결된 불변식 위반 항목이 없습니다.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* AttackSection 컴포넌트
 * - attackChains: 공격 체인 데이터 배열
 * - mitreMapping: MITRE 매핑 데이터 배열
 * - violations: 현재 대시보드에서 필터링된 불변식 위반 항목 배열
 * - activeFilter: 현재 선택된 전역 필터 (예: "전체", "소스 A", "소스 B" 등)
 * - 이 컴포넌트는 MITRE 히트맵과 공격 체인 카드를 렌더링하며, 전달된 props에 따라 표시되는 내용이 달라짐
 * - 예시: activeFilter가 "소스 A"로 설정되어 있고, violations 배열에 소스 A와 연결된 위반 항목이 5개 있다면, MITRE 히트맵은 이 5개 위반 항목과 연결된 기법을 색상으로 표시하고, 공격 체인 카드에는 이 위반 항목들과 연결된 단계 노드가 강조되어 표시됨
 */
export default function AttackSection({ attackChains, mitreMapping, violations = [], activeFilter = "전체" }) {
  // 공격 체인과 MITRE 매핑은 AI 분석이 완료되기 전 또는 위반 항목이 없을 때 null/undefined일 수 있음
  const chains  = attackChains ?? [];
  const mapping = mitreMapping  ?? [];

  const filteredViolations = violations.filter((v) =>
    activeFilter === "전체" || v.invariant_source === activeFilter
  );

  return (
    <div>
      <p style={sectionLabel}>AI 공격 시나리오 및 MITRE ATT&CK 매핑</p>
      <MitreHeatmap mitreMapping={mapping} violations={filteredViolations} />
      {chains.length === 0 ? (
        // 공격 체인이 아직 생성되지 않은 경우
        <div style={card}>
          <div style={{ padding: "32px 0", textAlign: "center" }}>
            <p style={{ fontSize: 13, color: "#73726c", margin: "0 0 6px" }}>분석된 공격 시나리오가 없습니다</p>
            <p style={{ fontSize: 11, color: "#b0aea8", margin: 0 }}>불변식 위반 항목 분석 후 AI가 공격 체인을 도출하면 여기에 표시됩니다</p>
          </div>
        </div>
      ) : (
        chains.map((chain) => (
          <AttackChain key={chain.chain_id} chain={chain} />
        ))
      )}
    </div>
  );
}

const sectionLabel = { fontSize: 11, fontWeight: 500, color: "#73726c", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 10 };
const card = { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: 16, marginBottom: 12 };
const cardTitle = { fontSize: 13, fontWeight: 500, marginBottom: 0 };
