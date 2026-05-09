import { useState } from "react";
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid } from "recharts";

const PRIORITY_STYLE = {
  즉시:   { bg: "#E6F1FB", text: "#0C447C" },
  "1주":  { bg: "#EEF4FD", text: "#185FA5" },
  "1개월": { bg: "#F0F6FE", text: "#378ADD" },
};

export default function DefenseSection({ coverage, scoreHistory, remediations: initialRemediations }) {
  // 스캔 완료 전 또는 첫 실행 시 각 데이터가 null/undefined일 수 있음
  const [remediations, setRemediations] = useState(initialRemediations ?? []);

  const safeCoverage = coverage     ?? {};
  const safeHistory  = scoreHistory ?? [];

  const radarData = Object.entries(safeCoverage).map(([phase, val]) => ({
    phase,
    현재: val.coverage_pct,
    목표: 80,
  }));

  const toggleDone = (idx) => {
    setRemediations((prev) =>
      prev.map((r, i) => (i === idx ? { ...r, done: !r.done } : r))
    );
  };

  return (
    <div>
      <p style={sectionLabel}>방어 방안 및 보안 수준</p>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
        {/* 레이더 차트 — 커버리지 데이터가 없으면 빈 상태 메시지 */}
        <div style={card}>
          <p style={cardTitle}>공격 단계별 방어 커버리지</p>
          {radarData.length === 0 ? (
            <div style={emptyState}>
              <p style={emptyMain}>방어 커버리지 데이터가 없습니다</p>
              <p style={emptySub}>스캔이 완료되면 공격 단계별 커버리지가 표시됩니다</p>
            </div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={220}>
                <RadarChart data={radarData}>
                  <PolarGrid stroke="rgba(0,0,0,0.08)" />
                  <PolarAngleAxis dataKey="phase" tick={{ fontSize: 11, fill: "#73726c" }} />
                  <Radar name="현재" dataKey="현재" stroke="#185FA5" fill="#185FA5" fillOpacity={0.15} />
                  <Radar name="목표" dataKey="목표" stroke="#85B7EB" fill="#85B7EB" fillOpacity={0.05} strokeDasharray="4 4" />
                </RadarChart>
              </ResponsiveContainer>
              <div style={{ display: "flex", gap: 12, fontSize: 11, color: "#73726c", justifyContent: "center" }}>
                <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 10, height: 10, background: "#185FA5", display: "inline-block", borderRadius: 2 }} />현재
                </span>
                <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 10, height: 10, background: "#85B7EB", display: "inline-block", borderRadius: 2 }} />목표 (80%)
                </span>
              </div>
            </>
          )}
        </div>

        {/* 꺾은선 그래프 — 스캔 이력이 없으면 빈 상태 메시지 */}
        <div style={card}>
          <p style={cardTitle}>보안 점수 추이 (회차별)</p>
          {safeHistory.length === 0 ? (
            <div style={emptyState}>
              <p style={emptyMain}>보안 점수 이력이 없습니다</p>
              <p style={emptySub}>여러 회차 스캔이 완료되면 추이가 표시됩니다</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={safeHistory} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
                <CartesianGrid stroke="rgba(0,0,0,0.06)" />
                <XAxis dataKey="scanned_at" tick={{ fontSize: 10, fill: "#73726c" }} tickFormatter={(v) => v.slice(5)} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "#73726c" }} />
                <Tooltip formatter={(v) => [`${v}점`, "보안 점수"]} labelFormatter={(l) => l} />
                <Line type="monotone" dataKey="score" stroke="#378ADD" strokeWidth={2} dot={{ fill: "#378ADD", r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* 개선 권고 목록 */}
      <div style={card}>
        <p style={cardTitle}>개선 권고 목록</p>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, tableLayout: "fixed" }}>
          <thead>
            <tr>
              {["연결 위반", "개선 방안", "공격단계", "우선순위", "조치"].map((h) => (
                <th key={h} style={th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {/* 개선 권고 항목이 없으면 빈 상태 메시지 */}
            {remediations.length === 0 ? (
              <tr>
                <td colSpan={5} style={{ textAlign: "center", padding: "24px", color: "#b0b0b0", fontSize: 12 }}>
                  등록된 개선 권고 항목이 없습니다
                </td>
              </tr>
            ) : remediations.map((r, idx) => {
              const ps = PRIORITY_STYLE[r.priority] || {};
              return (
                <tr key={r.invariant_id} style={{ opacity: r.done ? 0.4 : 1 }}>
                  <td style={td}>{r.invariant_id}</td>
                  <td style={{ ...td, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", textDecoration: r.done ? "line-through" : "none" }}>{r.description}</td>
                  <td style={td}>{r.attack_phase}</td>
                  <td style={td}>
                    <span style={{ background: ps.bg, color: ps.text, fontSize: 10, fontWeight: 500, padding: "2px 8px", borderRadius: 99 }}>
                      {r.priority}
                    </span>
                  </td>
                  <td style={td}>
                    <input type="checkbox" checked={r.done} onChange={() => toggleDone(idx)} style={{ cursor: "pointer" }} />
                  </td>
                </tr>
              );
            })}
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
const emptyState = { padding: "32px 0", textAlign: "center" };
const emptyMain  = { fontSize: 13, color: "#73726c", margin: "0 0 6px" };
const emptySub   = { fontSize: 11, color: "#b0aea8", margin: 0 };
