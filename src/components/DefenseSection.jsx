import { useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, ChipList, EmptyRow, SectionTitle } from "./common";

const PAGE_SIZE = 10;
const MAX_PAGE_BUTTONS = 10;

export default function DefenseSection({ summary = {}, timeline = { points: [] }, violations = [], activeScanId, scanCoverageMetrics = [] }) {
  const [highRiskPage, setHighRiskPage] = useState(1);
  const invariantTotal = summary.invariant_total ?? 0;
  const violatedCount = summary.violated_invariant_count ?? summary.total_violations ?? 0;
  const appliedCount = firstPositive(summary.applied_invariant_count, invariantTotal - violatedCount);
  const rawPoints = timeline.points ?? [];
  const activePoint = rawPoints.find((point) => point.run_id === activeScanId) ?? rawPoints.at(-1) ?? {};
  const activeMetrics = activePoint.metrics ?? {};
  const newViolationCount = firstNumber(summary.new_violations_since_previous_run, activeMetrics.new_violation_count, 0);
  const resolvedCount = firstNumber(summary.resolved_invariants_since_previous_run, activeMetrics.resolved_invariant_count, 0);
  const dayCounts = countByDay(rawPoints.map((point) => point.created_at));
  const points = rawPoints.map((point) => ({
    date: dayCounts[dateKey(point.created_at)] > 1 ? formatShortDateTime(point.created_at) : formatShortDate(point.created_at),
    tooltip_label: `${formatDate(point.created_at)} · ${point.run_id ?? "-"}`,
    confirmedViolation: metricNumber(point.metrics, ["confirmed_violation_count", "violated_invariant_count", "total_violations"], 0),
    unverifiable: metricNumber(point.metrics, ["unverifiable_invariant_count", "not_testable_invariant_count", "unknown_invariant_count"], 0),
    normalOrNotObserved: metricNumber(point.metrics, [
      "normal_or_not_observed_count",
      "normal_not_observed_count",
      "no_violation_observed_count",
      "applied_invariant_count",
    ], Math.max((point.metrics?.invariant_total ?? 0) - (point.metrics?.violated_invariant_count ?? 0), 0)),
    officialAttackChains: metricNumber(point.metrics, ["ai2_chain_scenario_count", "attack_chains", "attack_chains_count"], 0),
  }));
  const highRisk = violations.filter((item) => ["Critical", "High"].includes(item.severity));
  const highRiskTotalPages = Math.max(1, Math.ceil(highRisk.length / PAGE_SIZE));
  const currentHighRiskPage = Math.min(Math.max(highRiskPage, 1), highRiskTotalPages);
  const highRiskPageItems = highRisk.slice((currentHighRiskPage - 1) * PAGE_SIZE, currentHighRiskPage * PAGE_SIZE);

  return (
    <section>
      <SectionTitle title="방어 및 보안 수준" subtitle="AI 1차 검증 결과를 기반으로 보안 수준과 개선 우선순위를 확인합니다." />
      <div style={styles.kpiGrid}>
        <Metric label="적용된 불변식" value={appliedCount} />
        <Metric label="위반 불변식" value={violatedCount} />
        <Metric label="신규 위반" value={newViolationCount} />
        <Metric label="해결된 불변식" value={resolvedCount} />
      </div>
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>보안 상태 추이</h3>
        <ResponsiveContainer width="100%" height={240}>
          <LineChart data={points}>
            <CartesianGrid stroke="#eef2f6" />
            <XAxis dataKey="date" tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} />
            <Tooltip labelFormatter={formatTooltipLabel} />
            <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11 }} />
            <Line dataKey="confirmedViolation" name="확정 위반" stroke="#d92d20" strokeWidth={2} dot={{ r: 3 }} />
            <Line dataKey="unverifiable" name="검증 불가" stroke="#f79009" strokeWidth={2} dot={{ r: 3 }} />
            <Line dataKey="normalOrNotObserved" name="정상/위반 미관측" stroke="#12b76a" strokeWidth={2} dot={{ r: 3 }} />
            <Line dataKey="officialAttackChains" name="공식 공격 체인" stroke="#2f6fed" strokeWidth={2} strokeDasharray="5 5" dot={{ r: 3 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
      {scanCoverageMetrics.length > 0 && (
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>AI 분석 커버리지</h3>
          <div style={styles.coverageGrid}>
            {scanCoverageMetrics.map(({ metric, value }) => (
              <CoverageMetricCard key={metric} metric={metric} value={value} />
            ))}
          </div>
        </div>
      )}

      <div style={styles.card}>
        <div style={styles.tableHeader}>
          <h3 style={styles.cardTitle}>우선순위 개선 대상 (critical/high)</h3>
          <span style={styles.pageSummary}>
            {highRisk.length ? `${(currentHighRiskPage - 1) * PAGE_SIZE + 1}-${Math.min(currentHighRiskPage * PAGE_SIZE, highRisk.length)} / ${highRisk.length}` : "0 / 0"}
          </span>
        </div>
        <table style={styles.table}>
          <thead>
            <tr>{["불변식 ID", "심각도", "위반 사유", "Evidence", "자산"].map((head) => <th key={head} style={styles.th}>{head}</th>)}</tr>
          </thead>
          <tbody>
            {highRiskPageItems.map((item) => (
              <tr key={item.result_id ?? item.invariant_id}>
                <td style={styles.tdMono}>{item.invariant_id}</td>
                <td style={styles.td}><Badge value={item.severity} /></td>
                <td style={styles.td}>{item.summary ?? item.reason}</td>
                <td style={styles.td}><ChipList values={item.evidence_ids} /></td>
                <td style={styles.td}><ChipList values={item.affected_registry_asset_ids?.length ? item.affected_registry_asset_ids : item.asset_ids} /></td>
              </tr>
            ))}
            {!highRisk.length && <EmptyRow colSpan={5} text="Critical 또는 High 심각도의 AI1 위반 사항이 없습니다." />}
          </tbody>
        </table>
        <Pagination page={currentHighRiskPage} totalPages={highRiskTotalPages} onPageChange={setHighRiskPage} />
      </div>
    </section>
  );
}

function Metric({ label, value }) {
  return <div style={styles.metric}><span>{label}</span><strong>{value}</strong></div>;
}

function Pagination({ page, totalPages, onPageChange }) {
  if (totalPages <= 1) return null;
  const visiblePages = getVisiblePages(page, totalPages);
  return (
    <div style={styles.pagination}>
      <button type="button" onClick={() => onPageChange(Math.max(1, page - 1))} disabled={page <= 1} style={pageButton(false, page <= 1)}>이전</button>
      {visiblePages.map((pageNumber) => (
        <button
          key={pageNumber}
          type="button"
          onClick={() => onPageChange(pageNumber)}
          style={pageButton(page === pageNumber)}
        >
          {pageNumber}
        </button>
      ))}
      <button type="button" onClick={() => onPageChange(Math.min(totalPages, page + 1))} disabled={page >= totalPages} style={pageButton(false, page >= totalPages)}>다음</button>
    </div>
  );
}

function getVisiblePages(page, totalPages) {
  const blockStart = Math.floor((page - 1) / MAX_PAGE_BUTTONS) * MAX_PAGE_BUTTONS + 1;
  const blockEnd = Math.min(blockStart + MAX_PAGE_BUTTONS - 1, totalPages);
  return Array.from({ length: blockEnd - blockStart + 1 }, (_, index) => blockStart + index);
}

const METRIC_LABELS = {
  asset_count: "분석 자산",
  ai1_result_count: "AI1 불변식 판단",
  violated_invariant_count: "위반 불변식",
  ai2_scenario_count: "AI2 공격 시나리오",
  selected_evidence_count: "커버된 Evidence",
};

function CoverageMetricCard({ metric, value }) {
  const label = METRIC_LABELS[metric] ?? metric;
  const formatted = value >= 1000 ? value.toLocaleString() : value;
  return (
    <div style={styles.coverageCard}>
      <span style={styles.coverageLabel}>{label}</span>
      <strong style={styles.coverageValue}>{formatted}</strong>
    </div>
  );
}

function firstPositive(...values) {
  return values.find((value) => typeof value === "number" && value > 0) ?? 0;
}

function firstNumber(...values) {
  return values.find((value) => typeof value === "number") ?? 0;
}

function metricNumber(metrics = {}, keys = [], fallback = 0) {
  for (const key of keys) {
    const value = metrics?.[key];
    if (typeof value === "number") return value;
    if (value !== null && value !== undefined && value !== "" && !Number.isNaN(Number(value))) {
      return Number(value);
    }
  }
  return fallback;
}

function formatShortDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString("ko-KR", { month: "short", day: "numeric" });
}

function formatShortDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ko-KR", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ko-KR");
}

function formatTooltipLabel(label, payload = []) {
  return payload[0]?.payload?.tooltip_label ?? label;
}

function dateKey(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value ?? "";
  return date.toISOString().slice(0, 10);
}

function countByDay(values) {
  return values.reduce((counts, value) => {
    const key = dateKey(value);
    counts[key] = (counts[key] ?? 0) + 1;
    return counts;
  }, {});
}

function pageButton(active, disabled = false) {
  return {
    minWidth: 30,
    height: 30,
    border: `1px solid ${active ? "#185FA5" : "#e4e7ec"}`,
    borderRadius: 6,
    background: active ? "#185FA5" : disabled ? "#F8FAFC" : "#fff",
    color: active ? "#fff" : disabled ? "#C0C6D0" : "#667085",
    fontSize: 12,
    fontWeight: active ? 700 : 500,
    cursor: disabled ? "not-allowed" : "pointer",
  };
}

const styles = {
  coverageGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 10 },
  coverageCard: { background: "#F8FAFC", border: "1px solid #e4e7ec", borderRadius: 8, padding: "12px 14px", display: "flex", flexDirection: "column", gap: 6 },
  coverageLabel: { fontSize: 11, color: "#667085", fontWeight: 500 },
  coverageValue: { fontSize: 22, color: "#0C447C", fontWeight: 800 },
  kpiGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginBottom: 12 },
  metric: { background: "#fff", border: "1px solid #e4e7ec", borderRadius: 8, padding: 16, display: "flex", flexDirection: "column", gap: 8 },
  card: { background: "#fff", border: "1px solid #e4e7ec", borderRadius: 8, padding: 16, marginBottom: 12 },
  cardTitle: { margin: "0 0 12px", fontSize: 14 },
  tableHeader: { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 },
  pageSummary: { fontSize: 11, color: "#667085", whiteSpace: "nowrap", marginBottom: 12 },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 12 },
  th: { textAlign: "left", padding: "10px 12px", color: "#667085", borderBottom: "1px solid #e4e7ec" },
  td: { padding: "10px 12px", borderBottom: "1px solid #eef2f6", color: "#344054", verticalAlign: "top" },
  tdMono: { padding: "10px 12px", borderBottom: "1px solid #eef2f6", color: "#173b70", fontFamily: "monospace", fontWeight: 700 },
  pagination: { display: "flex", justifyContent: "center", alignItems: "center", gap: 6, marginTop: 14, flexWrap: "wrap" },
};
