import { useState } from "react";
import { PieChart, Pie, Cell, Tooltip, BarChart, Bar, XAxis, YAxis, ResponsiveContainer } from "recharts";

const SEVERITY_COLOR = {
  Critical: { bg: "#FEF1F1", text: "#C53030" },
  High:     { bg: "#FEF4EE", text: "#BF5520" },
  Medium:   { bg: "#FEF9E4", text: "#9C6F00" },
  Low:      { bg: "#F0FDF9", text: "#276749" },
};
const SEVERITY_CHART_COLOR = {
  Critical: "#E05252", High: "#F0874A", Medium: "#F6C142", Low: "#38A169",
};

// violation_reason → 위반 유형 레이블
const VIOLATION_TYPE = {
  clear_violation:      "명확한 위반",
  partial_satisfaction: "부분 충족",
  evidence_missing:     "증거 불충분",
  log_trace_gap:        "증거 불충분",
  not_determined:       "증거 불충분",
  control_not_observed: "검증 불가",
  environment_not_ready:"검증 불가",
};

// violation_reason → 드로어용 상세 레이블
const REASON_LABEL = {
  clear_violation:      { label: "명확한 위반",        bg: "#E6F1FB", text: "#0C447C" },
  partial_satisfaction: { label: "부분 충족",          bg: "#EEF4FD", text: "#185FA5" },
  not_determined:       { label: "판단 불가",          bg: "#F0F6FE", text: "#378ADD" },
  evidence_missing:     { label: "필수 Evidence 부족", bg: "#FEF3C7", text: "#92400E" },
  log_trace_gap:        { label: "로그/trace 단절",    bg: "#FEF3C7", text: "#92400E" },
  control_not_observed: { label: "통제 수행 미관찰",   bg: "#f1efea", text: "#73726c" },
  environment_not_ready:{ label: "환경 미준비",         bg: "#f1efea", text: "#73726c" },
};

const STATUS_LABEL = {
  violated: { label: "위반", bg: "#FEF1F1", text: "#C53030" },
  applied:  { label: "통과", bg: "#F0FDF9", text: "#276749" },
};

function Badge({ severity }) {
  const c = SEVERITY_COLOR[severity] || { bg: "#f1efea", text: "#444" };
  return (
    <span style={{ background: c.bg, color: c.text, fontSize: 10, fontWeight: 500, padding: "2px 8px", borderRadius: 99 }}>
      {severity}
    </span>
  );
}

function ViolationTypeBadge({ reason }) {
  const label = VIOLATION_TYPE[reason] ?? "-";
  return (
    <span style={{ fontSize: 11, color: "#73726c" }}>{label}</span>
  );
}

function StatusBadge({ status }) {
  const s = STATUS_LABEL[status] || { label: status, bg: "#f1efea", text: "#73726c" };
  return (
    <span style={{ background: s.bg, color: s.text, fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 99 }}>
      {s.label}
    </span>
  );
}

function ReasonBadge({ reason }) {
  if (!reason) return null;
  const r = REASON_LABEL[reason] || { label: reason, bg: "#f1efea", text: "#73726c" };
  return (
    <span style={{ background: r.bg, color: r.text, fontSize: 10, fontWeight: 500, padding: "2px 7px", borderRadius: 99 }}>
      {r.label}
    </span>
  );
}

// 신뢰도 바 — 중립 슬레이트 단색으로 통일 (severity 색과 경쟁 방지)
function ConfidenceBar({ value }) {
  const pct = Math.round((value ?? 0) * 100);
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
      <div style={{ width: 48, height: 4, background: "#E5E7EB", borderRadius: 99, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: "#94A3B8", borderRadius: 99 }} />
      </div>
      <span style={{ fontSize: 10, color: "#73726c" }}>{pct}%</span>
    </div>
  );
}

// 연관 자산 — 최대 2개 표시 후 +N
function AssetChips({ assetIds }) {
  if (!assetIds?.length) return <span style={{ color: "#b0aea8", fontSize: 11 }}>-</span>;
  const visible = assetIds.slice(0, 2);
  const rest    = assetIds.length - visible.length;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
      {visible.map((a) => (
        <span key={a} style={{ fontSize: 10, padding: "1px 6px", borderRadius: 4, background: "#F1F5F9", color: "#475569" }}>
          {a}
        </span>
      ))}
      {rest > 0 && (
        <span style={{ fontSize: 10, color: "#94A3B8" }}>+{rest}</span>
      )}
    </div>
  );
}

function calcSeverityDist(list) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  list.forEach((v) => { if (counts[v.severity] !== undefined) counts[v.severity]++; });
  return Object.entries(counts)
    .filter(([, val]) => val > 0)
    .map(([name, value]) => ({ name, value, color: SEVERITY_CHART_COLOR[name] }));
}

function calcZoneDist(list) {
  const counts = {};
  list.forEach((v) => { counts[v.server_zone] = (counts[v.server_zone] || 0) + 1; });
  return Object.entries(counts)
    .map(([zone, count]) => ({ zone, count }))
    .sort((a, b) => b.count - a.count);
}

function formatDetectedAt(dt) {
  if (!dt) return "-";
  const d = new Date(dt);
  if (isNaN(d.getTime())) return dt;
  return d.toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

// 위반 상세 드로어 ────────────────────────────────────────────────────────────
function DetailDrawer({ violation, onClose }) {
  const [visible, setVisible] = useState(false);
  useState(() => { requestAnimationFrame(() => setVisible(true)); });

  const handleClose = () => { setVisible(false); setTimeout(onClose, 220); };

  return (
    <>
      <div onClick={handleClose} style={{
        position: "fixed", inset: 0, background: "rgba(0,0,0,0.15)",
        zIndex: 100, opacity: visible ? 1 : 0, transition: "opacity 0.22s",
      }} />
      <div style={{
        position: "fixed", top: 0, right: 0, bottom: 0, width: 480,
        background: "#fff", zIndex: 101, display: "flex", flexDirection: "column",
        transform: visible ? "translateX(0)" : "translateX(100%)",
        transition: "transform 0.22s ease",
        boxShadow: "-4px 0 24px rgba(0,0,0,0.08)",
      }}>
        {/* 헤더 */}
        <div style={{ padding: "16px 20px", borderBottom: "0.5px solid rgba(0,0,0,0.08)", flexShrink: 0 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ marginBottom: 4 }}>
                <span style={{ fontFamily: "monospace", fontSize: 12, fontWeight: 600, color: "#0C447C" }}>
                  {violation.invariant_id || violation.id}
                </span>
              </div>
              <p style={{ fontSize: 13, fontWeight: 500, color: "#1a1a18", margin: 0 }}>
                {violation.description}
              </p>
            </div>
            <button onClick={handleClose} style={{ background: "none", border: "none", cursor: "pointer", fontSize: 22, color: "#73726c", padding: 0 }}>×</button>
          </div>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "16px 20px" }}>
          {/* AI 1 핵심 정보 */}
          <div style={{ background: "#f5f5f3", borderRadius: 10, padding: 14, marginBottom: 16 }}>
            <p style={{ fontSize: 10, fontWeight: 600, color: "#73726c", textTransform: "uppercase", letterSpacing: "0.06em", margin: "0 0 10px" }}>
              AI 1 판단 근거
            </p>
            <div style={{ display: "flex", gap: 16, marginBottom: 10 }}>
              <div>
                <p style={{ fontSize: 10, color: "#73726c", margin: "0 0 4px" }}>상태</p>
                <span style={{ fontSize: 11, color: "#1a1a18" }}>
                  {STATUS_LABEL[violation.status]?.label ?? violation.status}
                </span>
              </div>
              {violation.violation_reason && (
                <div>
                  <p style={{ fontSize: 10, color: "#73726c", margin: "0 0 4px" }}>위반 사유</p>
                  <span style={{ fontSize: 11, color: "#1a1a18" }}>
                    {REASON_LABEL[violation.violation_reason]?.label ?? violation.violation_reason}
                  </span>
                </div>
              )}
            </div>
            <div style={{ marginBottom: 10 }}>
              <p style={{ fontSize: 10, color: "#73726c", margin: "0 0 3px" }}>요약</p>
              <p style={{ fontSize: 12, color: "#1a1a18", margin: 0, lineHeight: 1.6 }}>{violation.summary}</p>
            </div>
            <div style={{ marginBottom: 10 }}>
              <p style={{ fontSize: 10, color: "#73726c", margin: "0 0 3px" }}>상세 이유</p>
              <p style={{ fontSize: 12, color: "#1a1a18", margin: 0, lineHeight: 1.6 }}>{violation.reason}</p>
            </div>
            <div style={{ display: "flex", gap: 16 }}>
              <div>
                <p style={{ fontSize: 10, color: "#73726c", margin: "0 0 4px" }}>신뢰도</p>
                <ConfidenceBar value={violation.confidence} />
              </div>
              <div>
                <p style={{ fontSize: 10, color: "#73726c", margin: "0 0 4px" }}>result_id</p>
                <span style={{ fontSize: 10, fontFamily: "monospace", color: "#73726c" }}>{violation.result_id}</span>
              </div>
            </div>
          </div>

          {/* 검증 가능 여부 */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 500, color: "#1a1a18" }}>현재 환경 검증 가능</span>
              <span style={{
                fontSize: 10, padding: "1px 7px", borderRadius: 99,
                background: violation.current_environment_testable ? "#E1F5EE" : "#f1efea",
                color: violation.current_environment_testable ? "#085041" : "#73726c",
              }}>
                {violation.current_environment_testable ? "가능" : "불가"}
              </span>
            </div>
            {violation.testability_reason && (
              <p style={{ fontSize: 11, color: "#73726c", margin: 0, lineHeight: 1.5 }}>
                {violation.testability_reason}
              </p>
            )}
          </div>

          {/* Evidence / Asset 참조 */}
          {violation.evidence_ids?.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <p style={{ fontSize: 10, color: "#73726c", margin: "0 0 5px", fontWeight: 500 }}>Evidence 참조</p>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {violation.evidence_ids.map((e) => (
                  <span key={e} style={{ fontSize: 10, padding: "2px 8px", borderRadius: 99, background: "#f0f6fe", color: "#185FA5", border: "0.5px solid #c8ddf0" }}>{e}</span>
                ))}
              </div>
            </div>
          )}
          {violation.asset_ids?.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <p style={{ fontSize: 10, color: "#73726c", margin: "0 0 5px", fontWeight: 500 }}>영향 자산</p>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {violation.asset_ids.map((a) => (
                  <span key={a} style={{ fontSize: 10, padding: "2px 8px", borderRadius: 99, background: "#f5f5f3", color: "#73726c" }}>{a}</span>
                ))}
              </div>
            </div>
          )}

          {/* 조치 방안 */}
          {violation.remediation && (
            <div style={{ background: "#E6F1FB", borderRadius: 8, padding: "10px 14px" }}>
              <p style={{ fontSize: 10, fontWeight: 600, color: "#0C447C", margin: "0 0 4px", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                권고 조치 ({violation.priority})
              </p>
              <p style={{ fontSize: 12, color: "#0C447C", margin: 0, lineHeight: 1.6 }}>{violation.remediation}</p>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// 메인 컴포넌트 ────────────────────────────────────────────────────────────────
export default function ViolationSection({ violations, activeFilter = "전체" }) {
  const [selected, setSelected] = useState(null);

  const filtered = violations.filter((v) => {
    if (activeFilter === "전체") return true;
    return v.invariant_source === activeFilter;
  });

  const severityDist = calcSeverityDist(filtered);
  const zoneDist     = calcZoneDist(filtered);

  return (
    <div>
      <p style={sectionLabel}>불변식 위반 현황</p>

      {/* 차트 2개 */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
        <div style={card}>
          <p style={cardTitle}>위험도 분포</p>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={severityDist} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" paddingAngle={2}>
                {severityDist.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
              </Pie>
              <Tooltip formatter={(value, name) => [`${value}건`, name]} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 8 }}>
            {severityDist.map((d) => (
              <span key={d.name} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "#73726c" }}>
                <span style={{ width: 10, height: 10, borderRadius: 2, background: d.color, display: "inline-block" }} />
                {d.name} {d.value}
              </span>
            ))}
          </div>
        </div>

        <div style={card}>
          <p style={cardTitle}>서버존별 위반 수</p>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={zoneDist} layout="vertical" margin={{ left: 10, right: 20 }}>
              <XAxis type="number" tick={{ fontSize: 11, fill: "#73726c" }} />
              <YAxis dataKey="zone" type="category" tick={{ fontSize: 11, fill: "#73726c" }} width={40} />
              <Tooltip />
              {/* Corporate 블루 — Critical 빨강과 구분, 집계 데이터임을 시각적으로 분리 */}
              <Bar dataKey="count" fill="#4E87D4" radius={[0, 4, 4, 0]} barSize={12} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 위반 목록 테이블 */}
      <div style={card}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
          <p style={{ ...cardTitle, marginBottom: 0 }}>위반 항목 목록</p>
          <span style={{ fontSize: 11, color: "#73726c" }}>{filtered.length}건</span>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, tableLayout: "fixed" }}>
          <thead>
            <tr>
              {["ID", "위험도", "위반 유형", "위반 항목", "서버존", "연관 자산", "신뢰도", "탐지 시각", ""].map((h) => (
                <th key={h} style={th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((v) => (
              <tr key={v.id || v.invariant_id} style={{ cursor: "pointer" }}
                  onClick={() => setSelected(v)}>
                <td style={{ ...td, fontFamily: "monospace", fontSize: 11 }}>
                  {v.invariant_id || v.id}
                </td>
                <td style={td}><Badge severity={v.severity} /></td>
                <td style={td}><ViolationTypeBadge reason={v.violation_reason} /></td>
                <td style={{ ...td, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {v.summary || v.description}
                </td>
                <td style={td}>{v.server_zone}</td>
                <td style={td}><AssetChips assetIds={v.asset_ids} /></td>
                <td style={td}><ConfidenceBar value={v.confidence} /></td>
                <td style={td}>{formatDetectedAt(v.detected_at || v.created_at)}</td>
                <td style={{ ...td, textAlign: "right" }}>
                  <span style={{ fontSize: 10, color: "#185FA5" }}>상세 →</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <DetailDrawer violation={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

const sectionLabel = { fontSize: 11, fontWeight: 500, color: "#73726c", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 10 };
const card         = { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: 16, marginBottom: 12 };
const cardTitle    = { fontSize: 13, fontWeight: 500, marginBottom: 14 };
const th = { textAlign: "left", color: "#73726c", fontWeight: 400, padding: "6px 8px", borderBottom: "0.5px solid rgba(0,0,0,0.1)" };
const td = { padding: "7px 8px", borderBottom: "0.5px solid rgba(0,0,0,0.08)", color: "#1a1a18" };
