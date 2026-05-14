import { useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, EmptyRow, SectionTitle } from "./common";
import { getInvariantSource } from "../utils/invariantSource";
import { buildInvariantJudgmentCounts, classifyInvariantJudgment } from "../utils/invariantJudgment";

const PAGE_SIZE = 10;
const MAX_PAGE_BUTTONS = 10;
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

export default function DefenseSection({ summary = {}, timeline = { points: [] }, violations = [], invariants = [], activeScanId }) {
  const [highRiskPage, setHighRiskPage] = useState(1);
  const invariantById = buildInvariantMap(invariants);
  const judgmentCounts = buildInvariantJudgmentCounts(invariants, violations);
  const invariantTotal = invariants.length || firstNumber(summary.invariant_total, violations.length);
  const confirmedViolationCount = judgmentCounts.confirmedViolation;
  const unverifiableCount = judgmentCounts.unverifiable;
  const normalOrNotObservedCount = judgmentCounts.normalOrNotObserved;
  const rawPoints = timeline.points ?? [];
  const dayCounts = countByDay(rawPoints.map((point) => point.created_at));
  const points = rawPoints.map((point, index) => {
    const isCurrentPoint = point.run_id === activeScanId || (!activeScanId && index === rawPoints.length - 1);
    const pointTotal = metricNumber(point.metrics, ["invariant_total"], invariantTotal);
    const pointConfirmed = metricNumber(point.metrics, ["confirmed_violation_count", "violated_invariant_count", "total_violations"], 0);
    const pointUnverifiable = metricNumber(point.metrics, ["unverifiable_invariant_count", "not_testable_invariant_count", "unknown_invariant_count"], 0);
    const pointNormal = metricNumber(point.metrics, [
      "normal_or_not_observed_count",
      "normal_not_observed_count",
      "no_violation_observed_count",
    ], Math.max(pointTotal - pointConfirmed - pointUnverifiable, 0));

    return {
      date: dayCounts[dateKey(point.created_at)] > 1 ? formatShortDateTime(point.created_at) : formatShortDate(point.created_at),
    tooltip_label: `${formatDate(point.created_at)} · ${point.run_id ?? "-"}`,
      confirmedViolation: isCurrentPoint ? confirmedViolationCount : pointConfirmed,
      unverifiable: isCurrentPoint ? unverifiableCount : pointUnverifiable,
      normalOrNotObserved: isCurrentPoint ? normalOrNotObservedCount : pointNormal,
    };
  });
  const highRisk = violations
    .filter((item) => ["critical", "high"].includes(normalizeText(item.severity)))
    .sort((a, b) => {
      const impactDiff = affectedAssetCount(b) - affectedAssetCount(a);
      if (impactDiff !== 0) return impactDiff;
      return (SEVERITY_ORDER[normalizeText(a.severity)] ?? 9) - (SEVERITY_ORDER[normalizeText(b.severity)] ?? 9);
    });
  const highRiskTotalPages = Math.max(1, Math.ceil(highRisk.length / PAGE_SIZE));
  const currentHighRiskPage = Math.min(Math.max(highRiskPage, 1), highRiskTotalPages);
  const highRiskPageItems = highRisk.slice((currentHighRiskPage - 1) * PAGE_SIZE, currentHighRiskPage * PAGE_SIZE);

  return (
    <section>
      <SectionTitle title="방어 및 보안 수준" subtitle="AI 1차 검증 결과를 기반으로 보안 수준과 개선 우선순위를 확인합니다." />
      <div style={styles.kpiGrid}>
        <Metric label="전체 불변식" value={invariantTotal} />
        <Metric label="확정 위반" value={confirmedViolationCount} />
        <Metric label="검증 불가" value={unverifiableCount} />
        <Metric label="정상/위반 미관측" value={normalOrNotObservedCount} />
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
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div style={styles.card}>
        <div style={styles.tableHeader}>
          <h3 style={styles.cardTitle}>우선순위 개선 대상 (critical/high)</h3>
          <span style={styles.pageSummary}>
            {highRisk.length ? `${(currentHighRiskPage - 1) * PAGE_SIZE + 1}-${Math.min(currentHighRiskPage * PAGE_SIZE, highRisk.length)} / ${highRisk.length}` : "0 / 0"}
          </span>
        </div>
        <table style={styles.table}>
          <colgroup>
            <col style={{ width: 138 }} />
            <col style={{ width: 92 }} />
            <col style={{ width: 74 }} />
            <col style={{ width: 86 }} />
            <col style={{ width: "auto" }} />
            <col style={{ width: 132 }} />
            <col style={{ width: 176 }} />
            <col style={{ width: 220 }} />
          </colgroup>
          <thead>
            <tr>{["불변식 ID", "심각도", "분류", "category", "불변식 내용", "검증 상태", "위반 사유", "개선 권고사항"].map((head) => <th key={head} style={styles.th}>{head}</th>)}</tr>
          </thead>
          <tbody>
            {highRiskPageItems.map((item) => {
              const invariant = invariantById[item.invariant_id];
              return (
                <tr key={item.result_id ?? item.invariant_id}>
                  <td style={styles.tdMono}>{item.invariant_id}</td>
                  <td style={styles.td}><Badge value={item.severity} /></td>
                  <td style={styles.td}>{formatSourceLabel(item.invariant_source ?? invariant?.invariant_source ?? item.source)}</td>
                  <td style={styles.td}>{formatCategory(item, invariant)}</td>
                  <td style={styles.td}>{displayInvariantContent(item, invariant)}</td>
                  <td style={styles.td}>{formatJudgmentStatus(item, invariant)}</td>
                  <td style={styles.td}>{formatViolationReason(item.violation_reason ?? invariant?.violation_reason)}</td>
                  <td style={styles.td}>{formatRecommendation(item)}</td>
                </tr>
              );
            })}
            {!highRisk.length && <EmptyRow colSpan={8} text="Critical 또는 High 심각도의 AI1 위반 사항이 없습니다." />}
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
      <button type="button" onClick={() => onPageChange(Math.max(1, page - 1))} disabled={page <= 1} style={pageButton(false, page <= 1)}>‹</button>
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
      <button type="button" onClick={() => onPageChange(Math.min(totalPages, page + 1))} disabled={page >= totalPages} style={pageButton(false, page >= totalPages)}>›</button>
    </div>
  );
}

function getVisiblePages(page, totalPages) {
  const blockStart = Math.floor((page - 1) / MAX_PAGE_BUTTONS) * MAX_PAGE_BUTTONS + 1;
  const blockEnd = Math.min(blockStart + MAX_PAGE_BUTTONS - 1, totalPages);
  return Array.from({ length: blockEnd - blockStart + 1 }, (_, index) => blockStart + index);
}

function firstNumber(...values) {
  for (const value of values) {
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (value !== null && value !== undefined && value !== "" && !Number.isNaN(Number(value))) return Number(value);
  }
  return 0;
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

function buildInvariantMap(invariants) {
  return Object.fromEntries(
    invariants
      .map((invariant) => [invariant.invariant_id ?? invariant.id, invariant])
      .filter(([id]) => id)
  );
}

function formatSourceLabel(value) {
  const source = getInvariantSource({ source: value });
  if (source === "fixed") return "고정";
  if (source === "custom") return "가변";
  return value ?? "-";
}

function formatCategory(violation, invariant) {
  return violation.category ?? violation.type ?? invariant?.category ?? invariant?.type ?? "-";
}

function displayInvariantContent(violation, invariant) {
  const id = violation.invariant_id ?? violation.id;
  const candidates = [
    invariant?.title,
    invariant?.name,
    invariant?.catalog_title,
    invariant?.description,
    violation.description,
    violation.summary,
  ];
  return candidates.find((value) => value && value !== id) ?? "-";
}

function formatJudgmentStatus(violation, invariant) {
  const judgment = classifyInvariantJudgment({ ...(invariant ?? {}), ...violation });
  if (judgment === "confirmedViolation") return "확정 위반";
  if (judgment === "unverifiable") return "검증 불가";
  return "정상/위반 미관측";
}

function formatViolationReason(value) {
  const labels = {
    clear_violation: "구조화된 조건값 위반",
    partial_satisfaction: "부분 충족/부분위반",
    evidence_missing: "증거 부족",
    control_not_observed: "통제 미관측",
  };
  return labels[value] ?? value ?? "-";
}

function affectedAssetCount(item) {
  return uniqueList(
    item.asset_ids,
    item.affected_asset_ids,
    item.affected_registry_asset_ids,
    item.affected_resources,
    item.affected_assets?.map?.((asset) => asset?.asset_id ?? asset?.id ?? asset)
  ).length;
}

function formatRecommendation(item) {
  return firstText(
    item.remediation,
    item.recommended_action,
    item.recommendation,
    item.mitigation,
    item.fix,
    item.remediation_items?.[0]?.description,
    item.remediation_items?.[0]?.recommended_action
  );
}

function firstText(...values) {
  const value = values.find((item) => item !== null && item !== undefined && String(item).trim());
  return value ? String(value) : "-";
}

function uniqueList(...values) {
  return [...new Set(values.flatMap((value) => Array.isArray(value) ? value : value ? [value] : []).filter(Boolean))];
}

function normalizeText(value) {
  return String(value ?? "").trim().toLowerCase();
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
  kpiGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginBottom: 12 },
  metric: { background: "#fff", border: "1px solid #e4e7ec", borderRadius: 8, padding: 16, display: "flex", flexDirection: "column", gap: 8 },
  card: { background: "#fff", border: "1px solid #e4e7ec", borderRadius: 8, padding: 16, marginBottom: 12 },
  cardTitle: { margin: "0 0 12px", fontSize: 14 },
  tableHeader: { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 },
  pageSummary: { fontSize: 11, color: "#667085", whiteSpace: "nowrap", marginBottom: 12 },
  table: { width: "100%", borderCollapse: "collapse", tableLayout: "fixed", fontSize: 12 },
  th: { textAlign: "left", padding: "10px 12px", color: "#667085", borderBottom: "1px solid #e4e7ec" },
  td: { padding: "10px 12px", borderBottom: "1px solid #eef2f6", color: "#344054", verticalAlign: "top", wordBreak: "break-word" },
  tdMono: { padding: "10px 12px", borderBottom: "1px solid #eef2f6", color: "#173b70", fontFamily: "monospace", fontWeight: 700 },
  pagination: { display: "flex", justifyContent: "center", alignItems: "center", gap: 6, marginTop: 14, flexWrap: "wrap" },
};


