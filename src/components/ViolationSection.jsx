/*
 * 취약점 발견 현황 page의 [불변식 위반 현황]을 보여주는 컴포넌트
 *
 * - 전체/고정/가변 불변식 위반 수와 비율을 KPI 카드로 표시
 * - 위험도 분포를 도넛 차트로 시각화
 * - 서버존별 위반 수를 수평 막대그래프로 시각화
 * - 위반 항목 목록을 테이블로 표시 (위험도 순 정렬)
 */

import { PieChart, Pie, Cell, Tooltip, BarChart, Bar, XAxis, YAxis, ResponsiveContainer } from "recharts";

const SEVERITY_COLOR = {
  Critical: { bg: "#E6F1FB", text: "#0C447C" },
  High:     { bg: "#EEF4FD", text: "#185FA5" },
  Medium:   { bg: "#F0F6FE", text: "#378ADD" },
  Low:      { bg: "#E1F5EE", text: "#085041" },
};

const SEVERITY_CHART_COLOR = {
  Critical: "#0C447C",
  High:     "#185FA5",
  Medium:   "#378ADD",
  Low:      "#85B7EB",
};


/* 위험도 severity에 따른 색상 배지 컴포넌트 */
function Badge({ severity }) {
  const c = SEVERITY_COLOR[severity] || { bg: "#f1efea", text: "#444" };
  return (
    <span style={{ background: c.bg, color: c.text, fontSize: 10, fontWeight: 500, padding: "2px 8px", borderRadius: 99 }}>
      {severity}
    </span>
  );
}

/* violations 배열로부터 위험도 분포 계산 (critical과 high 갯수)*/
function calcSeverityDist(list) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  list.forEach((v) => { if (counts[v.severity] !== undefined) counts[v.severity]++; });
  // 차트용 데이터로 변환, 0인건 제거
  return Object.entries(counts)
    .filter(([, value]) => value > 0)
    .map(([name, value]) => ({ name, value, color: SEVERITY_CHART_COLOR[name] }));
}

/* violations 배열로부터 서버존별 집계 계산 */
function calcZoneDist(list) {
  const counts = {};
  list.forEach((v) => {
    counts[v.server_zone] = (counts[v.server_zone] || 0) + 1;
  });
  // 차트용 데이터로 변환(배열로 변환하고 정렬) 
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

export default function ViolationSection({ violations, activeFilter = "전체" }) {
  /* activeFilter에 따라 데이터 필터링
   * - "전체"인 경우 모든 데이터를 보여주고, "fixed" 또는 "variable"인 경우 해당 데이터만 보여줌 
   */
  const filtered = violations.filter((v) => {
    if (activeFilter === "전체") return true;
    return v.invariant_source === activeFilter;
  });
  
  /* 필터링된 데이터로 차트 데이터 계산 */
  const severityDist = calcSeverityDist(filtered);
  const zoneDist = calcZoneDist(filtered);

  return (
    <div>
      <p style={sectionLabel}>불변식 위반 현황</p>

      {/* 차트 2개 */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>

        {/* 도넛 차트 */}
        <div style={card}>
          <p style={cardTitle}>위험도 분포</p>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={severityDist} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" paddingAngle={2}>
                {severityDist.map((entry) => (
                  <Cell key={entry.name} fill={entry.color} />
                ))}
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

        {/* 수평 막대 */}
        <div style={card}>
          <p style={cardTitle}>서버존별 위반 수</p>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={zoneDist} layout="vertical" margin={{ left: 10, right: 20 }}>
              <XAxis type="number" tick={{ fontSize: 11, fill: "#73726c" }} />
              <YAxis dataKey="zone" type="category" tick={{ fontSize: 11, fill: "#73726c" }} width={40} />
              <Tooltip />
              <Bar dataKey="count" fill="#378ADD" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 위반 목록 테이블 */}
      <div style={card}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
          <p style={{ ...cardTitle, marginBottom: 0 }}>위반 항목 목록 (우선순위 정렬)</p>
          <span style={{ fontSize: 11, color: "#73726c" }}>{filtered.length}건</span>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, tableLayout: "fixed" }}>
          <thead>
            <tr>
              {["ID", "위험도", "위반 항목", "서버존", "유형", "구분", "탐지 시각"].map((h) => (
                <th key={h} style={th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((v) => (
              <tr key={v.id}>
                <td style={td}>{v.id}</td>
                <td style={td}><Badge severity={v.severity} /></td>
                <td style={{ ...td, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.description}</td>
                <td style={td}>{v.server_zone}</td>
                <td style={td}>{v.type}</td>
                <td style={td}>
                  <span style={{
                    fontSize: 10, padding: "2px 7px", borderRadius: 99, fontWeight: 500,
                    background: v.invariant_source === "fixed" ? "#E6F1FB" : "#F0F6FE",
                    color: v.invariant_source === "fixed" ? "#0C447C" : "#378ADD",
                  }}>
                    {v.invariant_source === "fixed" ? "고정" : "가변"}
                  </span>
                </td>
                <td style={td}>{formatDetectedAt(v.detected_at)}</td>
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
