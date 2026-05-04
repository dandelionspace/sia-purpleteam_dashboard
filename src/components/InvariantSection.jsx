/*
 * 불변식 목록을 보여주는 컴포넌트
 * - 고정/가변 불변식 구분, 카테고리, 위험도, 상태 등의 정보를 테이블로 표시
 * - 출처(고정/가변)와 상태(통과/위반)로 필터링 가능
 * - KPI 카드: 전체 불변식 수, 고정/가변 불변식 수, 전체 위반율
 * - 고정/가변 불변식의 위반율을 게이지 형태로 시각화
 * - 카테고리별 통과/위반 현황을 막대그래프로 시각화
 */

import { useState } from "react";
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip } from "recharts";

const SOURCE_TABS = [
  { id: "전체",     label: "전체" },
  { id: "fixed",    label: "고정 불변식" },
  { id: "variable", label: "가변 불변식" },
];

const STATUS_TABS = [
  { id: "전체",    label: "전체" },
  { id: "passed",  label: "통과" },
  { id: "violated", label: "위반" },
];

const SEVERITY_COLOR = {
  Critical: { bg: "#E6F1FB", text: "#0C447C" },
  High:     { bg: "#EEF4FD", text: "#185FA5" },
  Medium:   { bg: "#F0F6FE", text: "#378ADD" },
  Low:      { bg: "#E1F5EE", text: "#085041" },
};

function Badge({ severity }) {
  const c = SEVERITY_COLOR[severity] || { bg: "#f1efea", text: "#444" };
  return (
    <span style={{ background: c.bg, color: c.text, fontSize: 10, fontWeight: 500, padding: "2px 8px", borderRadius: 99 }}>
      {severity}
    </span>
  );
}

function ViolationRateBar({ label, violated, total }) {
  const pct = total === 0 ? 0 : Math.round((violated / total) * 100);
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 5 }}>
        <span style={{ color: "#1a1a18", fontWeight: 500 }}>{label}</span>
        <span style={{ color: "#0C447C", fontWeight: 500 }}>{pct}% ({violated}/{total})</span>
      </div>
      <div style={{ height: 8, background: "#E6F1FB", borderRadius: 99, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: "#0C447C", borderRadius: 99, transition: "width 0.3s" }} />
      </div>
    </div>
  );
}

export default function InvariantSection({ invariants: propInvariants }) {
  const invariants = propInvariants ?? [];
  const [sourceTab, setSourceTab] = useState("전체");
  const [statusTab, setStatusTab] = useState("전체");

  const filtered = invariants.filter((inv) => {
    const sourceMatch = sourceTab === "전체" || inv.source === sourceTab;
    const statusMatch = statusTab === "전체" || inv.status === statusTab;
    return sourceMatch && statusMatch;
  });

  // KPI 계산
  const total = invariants.length;
  const fixed = invariants.filter((i) => i.source === "fixed").length;
  const variable = invariants.filter((i) => i.source === "variable").length;
  const violated = invariants.filter((i) => i.status === "violated").length;
  const violationRate = Math.round((violated / total) * 100);

  const fixedViolated = invariants.filter((i) => i.source === "fixed" && i.status === "violated").length;
  const variableViolated = invariants.filter((i) => i.source === "variable" && i.status === "violated").length;

  // 카테고리별 통과/위반 집계
  const categoryStats = [...new Set(invariants.map((i) => i.category))].map((cat) => {
    const catItems = invariants.filter((i) => i.category === cat);
    const catFiltered = sourceTab === "전체" ? catItems : catItems.filter((i) => i.source === sourceTab);
    return {
      category: cat,
      통과: catFiltered.filter((i) => i.status === "passed").length,
      위반: catFiltered.filter((i) => i.status === "violated").length,
    };
  }).filter((c) => c.통과 + c.위반 > 0);

  return (
    <div>
      <p style={sectionLabel}>불변식 목록</p>

      {/* KPI */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
        {[
          { label: "전체 불변식", value: total, color: "#1a1a18" },
          { label: "고정 불변식", value: fixed, color: "#0C447C" },
          { label: "가변 불변식", value: variable, color: "#378ADD" },
          { label: "전체 위반율", value: `${violationRate}%`, color: "#0C447C" },
        ].map((k) => (
          <div key={k.label} style={{ background: "#f5f5f3", borderRadius: 8, padding: "14px 16px" }}>
            <p style={{ fontSize: 12, color: "#73726c", marginBottom: 6 }}>{k.label}</p>
            <p style={{ fontSize: 22, fontWeight: 500, color: k.color, margin: 0 }}>{k.value}</p>
          </div>
        ))}
      </div>

      {/* 통과율 + 카테고리 차트 */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>

        {/* 위반율 게이지 */}
        <div style={card}>
          <p style={cardTitle}>고정/가변 위반율</p>
          <ViolationRateBar label="고정 불변식" violated={fixedViolated} total={fixed} />
          <ViolationRateBar label="가변 불변식" violated={variableViolated} total={variable} />
          <ViolationRateBar label="전체" violated={violated} total={total} />
        </div>

        {/* 카테고리별 통과/위반 */}
        <div style={card}>
          <p style={cardTitle}>카테고리별 현황</p>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={categoryStats} layout="vertical" margin={{ left: 10, right: 20 }}>
              <XAxis type="number" tick={{ fontSize: 11, fill: "#73726c" }} />
              <YAxis dataKey="category" type="category" tick={{ fontSize: 11, fill: "#73726c" }} width={52} />
              <Tooltip />
              <Bar dataKey="통과" stackId="a" fill="#E6F1FB" radius={[0, 0, 0, 0]} />
              <Bar dataKey="위반" stackId="a" fill="#185FA5" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", gap: 12, marginTop: 6, fontSize: 11, color: "#73726c" }}>
            <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <span style={{ width: 10, height: 10, borderRadius: 2, background: "#E6F1FB", display: "inline-block" }} />통과
            </span>
            <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <span style={{ width: 10, height: 10, borderRadius: 2, background: "#185FA5", display: "inline-block" }} />위반
            </span>
          </div>
        </div>
      </div>

      {/* 필터 */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
        {/* 출처 탭 */}
        <div style={{ display: "flex", gap: 6 }}>
          {SOURCE_TABS.map((tab) => (
            <button key={tab.id} onClick={() => setSourceTab(tab.id)} style={{
              padding: "5px 14px", borderRadius: 99, border: "0.5px solid",
              fontSize: 12, cursor: "pointer",
              borderColor: sourceTab === tab.id ? "#185FA5" : "rgba(0,0,0,0.12)",
              background: sourceTab === tab.id ? "#185FA5" : "transparent",
              color: sourceTab === tab.id ? "#fff" : "#73726c",
              fontWeight: sourceTab === tab.id ? 500 : 400,
            }}>
              {tab.label}
              <span style={{
                marginLeft: 6, fontSize: 10,
                background: sourceTab === tab.id ? "rgba(255,255,255,0.25)" : "rgba(0,0,0,0.06)",
                padding: "1px 6px", borderRadius: 99,
                color: sourceTab === tab.id ? "#fff" : "#73726c",
              }}>
                {invariants.filter((i) => tab.id === "전체" || i.source === tab.id).length}
              </span>
            </button>
          ))}
        </div>

        {/* 상태 탭 */}
        <div style={{ display: "flex", gap: 6 }}>
          {STATUS_TABS.map((tab) => {
            const isActive = statusTab === tab.id;
            const dotColor = tab.id === "passed" ? "#0F6E56" : tab.id === "violated" ? "#0C447C" : "#73726c";
            return (
              <button key={tab.id} onClick={() => setStatusTab(tab.id)} style={{
                padding: "5px 14px", borderRadius: 99, border: "0.5px solid",
                fontSize: 12, cursor: "pointer",
                borderColor: isActive ? dotColor : "rgba(0,0,0,0.12)",
                background: isActive ? dotColor : "transparent",
                color: isActive ? "#fff" : "#73726c",
                fontWeight: isActive ? 500 : 400,
                display: "flex", alignItems: "center", gap: 4,
              }}>
                {tab.id === "passed" && <span>✓</span>}
                {tab.id === "violated" && <span>●</span>}
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* 불변식 테이블 */}
      <div style={card}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
          <p style={{ ...cardTitle, marginBottom: 0 }}>불변식 목록</p>
          <span style={{ fontSize: 11, color: "#73726c" }}>{filtered.length}건</span>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, tableLayout: "fixed" }}>
          <thead>
            <tr>
              {["ID", "불변식 내용", "분류", "카테고리", "위험도", "상태", "근거"].map((h) => (
                <th key={h} style={th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((inv) => (
              <tr key={inv.id}>
                <td style={{ ...td, fontFamily: "monospace", fontSize: 11 }}>{inv.id}</td>
                <td style={{ ...td, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{inv.description}</td>
                <td style={td}>
                  <span style={{
                    fontSize: 10, padding: "2px 7px", borderRadius: 99, fontWeight: 500,
                    background: inv.source === "fixed" ? "#E6F1FB" : "#F0F6FE",
                    color: inv.source === "fixed" ? "#0C447C" : "#378ADD",
                  }}>
                    {inv.source === "fixed" ? "고정" : "가변"}
                  </span>
                </td>
                <td style={{ ...td, color: "#73726c" }}>{inv.category}</td>
                <td style={td}><Badge severity={inv.severity} /></td>
                <td style={td}>
                  {inv.status === "passed" ? (
                    <span style={{ color: "#0F6E56", fontWeight: 500, fontSize: 12 }}>✓ 통과</span>
                  ) : (
                    <span style={{ color: "#0C447C", fontWeight: 500, fontSize: 12 }}>위반</span>
                  )}
                </td>
                <td style={{ ...td, color: "#73726c", fontSize: 11 }}>{inv.reference}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const sectionLabel = { fontSize: 11, fontWeight: 500, color: "#73726c", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 10 };
const card = { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: 16, marginBottom: 12 };
const cardTitle = { fontSize: 13, fontWeight: 500, marginBottom: 14 };
const th = { textAlign: "left", color: "#73726c", fontWeight: 400, padding: "6px 8px", borderBottom: "0.5px solid rgba(0,0,0,0.1)" };
const td = { padding: "7px 8px", borderBottom: "0.5px solid rgba(0,0,0,0.08)", color: "#1a1a18" };
