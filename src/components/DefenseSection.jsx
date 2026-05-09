import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, ChipList, EmptyRow, SectionTitle } from "./common";

export default function DefenseSection({ summary = {}, timeline = { points: [] }, violations = [] }) {
  const points = (timeline.points ?? []).map((point) => ({
    date: formatShortDate(point.created_at),
    violated: point.metrics?.violated_invariant_count ?? 0,
    applied: point.metrics?.applied_invariant_count ?? 0,
    chains: point.metrics?.ai2_chain_scenario_count ?? 0,
  }));
  const highRisk = violations.filter((item) => ["Critical", "High"].includes(item.severity));

  return (
    <section>
      <SectionTitle title="보안 현황" subtitle="AI 1의 결과에 기반한 보안 수준과 타임라인 " />
      <div style={styles.kpiGrid}>
        <Metric label="적용된 불변식" value={summary.applied_invariant_count ?? 0} />
        <Metric label="위반된 불변식" value={summary.violated_invariant_count ?? 0} />
        <Metric label="새로운 위반 수" value={summary.new_violations_since_previous_run ?? 0} />
        <Metric label="해결된 불변식" value={summary.resolved_invariants_since_previous_run ?? 0} />
      </div>
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>보안 상태 추이</h3>
        <ResponsiveContainer width="100%" height={240}>
          <LineChart data={points}>
            <CartesianGrid stroke="#eef2f6" />
            <XAxis dataKey="date" tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} />
            <Tooltip />
            <Line dataKey="violated" name="Violated invariants" stroke="#d92d20" strokeWidth={2} />
            <Line dataKey="applied" name="Applied invariants" stroke="#12b76a" strokeWidth={2} />
            <Line dataKey="chains" name="AI2 chains" stroke="#2f6fed" strokeWidth={2} />
          </LineChart>
        </ResponsiveContainer>
      </div>
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>우선 순위 개선 대상 (critical/high)</h3>
        <table style={styles.table}>
          <thead><tr>{["불변식 ID", "심각도", "위반 사유", "Evidence", "자산"].map((head) => <th key={head} style={styles.th}>{head}</th>)}</tr></thead>
          <tbody>
            {highRisk.map((item) => (
              <tr key={item.result_id ?? item.invariant_id}>
                <td style={styles.tdMono}>{item.invariant_id}</td>
                <td style={styles.td}><Badge value={item.severity} /></td>
                <td style={styles.td}>{item.summary ?? item.reason}</td>
                <td style={styles.td}><ChipList values={item.evidence_ids} /></td>
                <td style={styles.td}><ChipList values={item.asset_ids} /></td>
              </tr>
            ))}
            {!highRisk.length && <EmptyRow colSpan={5} text="Critical 또는 High 심각도의 AI1 위반 사항이 없습니다" />}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Metric({ label, value }) {
  return <div style={styles.metric}><span>{label}</span><strong>{value}</strong></div>;
}

function formatShortDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString("ko-KR", { month: "short", day: "numeric" });
}

const styles = {
  kpiGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginBottom: 12 },
  metric: { background: "#fff", border: "1px solid #e4e7ec", borderRadius: 8, padding: 16, display: "flex", flexDirection: "column", gap: 8 },
  card: { background: "#fff", border: "1px solid #e4e7ec", borderRadius: 8, padding: 16, marginBottom: 12 },
  cardTitle: { margin: "0 0 12px", fontSize: 14 },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 12 },
  th: { textAlign: "left", padding: "10px 12px", color: "#667085", borderBottom: "1px solid #e4e7ec" },
  td: { padding: "10px 12px", borderBottom: "1px solid #eef2f6", color: "#344054", verticalAlign: "top" },
  tdMono: { padding: "10px 12px", borderBottom: "1px solid #eef2f6", color: "#173b70", fontFamily: "monospace", fontWeight: 700 },
};
