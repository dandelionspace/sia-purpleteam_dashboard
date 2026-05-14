import { useMemo, useState } from "react";
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, EmptyRow, SectionTitle } from "./common";
import { getInvariantSource, sourceMatches } from "../utils/invariantSource";
import { buildInvariantJudgmentCounts, classifyInvariantJudgment } from "../utils/invariantJudgment";
import { formatServerZone, formatServerZones } from "../utils/zoneDisplay";

const SEVERITY_CHART_COLOR = {
  Critical: "#E05252",
  High: "#F0874A",
  Medium: "#F6C142",
  Low: "#38A169",
};
const PAGE_SIZE = 10;
const MAX_PAGE_BUTTONS = 10;
const SEVERITY_SORT = { Critical: 0, High: 1, Medium: 2, Low: 3 };
const JUDGMENT_FILTERS = [
  { id: "all", label: "전체" },
  { id: "confirmedViolation", label: "확정 위반" },
  { id: "unverifiable", label: "검증 불가" },
  { id: "normalOrNotObserved", label: "정상/위반 미관측" },
];

export default function ViolationSection({ violations = [], assets = [], invariants = [], activeFilter = "all", onOpenEvidence = null }) {
  const [page, setPage] = useState(1);
  const [judgmentFilter, setJudgmentFilter] = useState("all");
  const invariantById = useMemo(() => buildInvariantMap(invariants), [invariants]);
  const judgmentRows = useMemo(() => buildJudgmentRows(invariants, violations), [invariants, violations]);
  const sourceFiltered = activeFilter === "all"
    ? judgmentRows
    : judgmentRows.filter((item) => sourceMatches(item.invariant_source ?? invariantById[item.invariant_id]?.invariant_source ?? item.source, activeFilter));
  const filtered = judgmentFilter === "all"
    ? sourceFiltered
    : sourceFiltered.filter((item) => getJudgmentKey(item, invariantById[item.invariant_id]) === judgmentFilter);
  const judgmentCounts = calcJudgmentFilterCounts(sourceFiltered);
  const sourceRateStats = calcSourceRateStats(judgmentRows, invariants);
  const severityDist = calcSeverityDist(filtered);
  const zoneDist = calcZoneDist(filtered, assets);
  const sorted = [...filtered].sort((a, b) => {
    const severityDiff = (SEVERITY_SORT[a.severity] ?? 4) - (SEVERITY_SORT[b.severity] ?? 4);
    if (severityDiff !== 0) return severityDiff;
    return normalizeConfidence(b.confidence) - normalizeConfidence(a.confidence);
  });
  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const currentPage = Math.min(Math.max(page, 1), totalPages);
  const pageItems = sorted.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  return (
    <section>
      <SectionTitle title="불변식 위반 현황" subtitle="AI1 검증 결과 기준의 위반 목록과 판단 근거입니다." />
      <div style={styles.chartGrid}>
        <div style={styles.rateCard}>
          <h3 style={styles.chartTitle}>고정/가변 위반률</h3>
          {sourceRateStats.map((item) => (
            <ViolationRateBar key={item.label} {...item} />
          ))}
        </div>

        <div style={styles.chartCard}>
          <h3 style={styles.chartTitle}>위험도 분포</h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={severityDist} cx="50%" cy="50%" innerRadius={48} outerRadius={78} dataKey="value" paddingAngle={2}>
                {severityDist.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
              </Pie>
              <Tooltip formatter={(value, name) => [`${value}건`, name]} />
            </PieChart>
          </ResponsiveContainer>
          <div style={styles.legendRow}>
            {severityDist.map((item) => (
              <span key={item.name} style={styles.legendItem}>
                <span style={{ ...styles.legendSwatch, background: item.color }} />
                {item.name} {item.value}
              </span>
            ))}
            {!severityDist.length && <span style={styles.emptyChartText}>No severity data</span>}
          </div>
        </div>

        <div style={styles.chartCard}>
          <h3 style={styles.chartTitle}>자산 존별 위반 수</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={zoneDist} layout="vertical" margin={{ top: 8, right: 28, bottom: 8, left: 8 }}>
              <XAxis type="number" tick={{ fontSize: 11, fill: "#73726c" }} axisLine={{ stroke: "#A3A3A3" }} tickLine={{ stroke: "#A3A3A3" }} allowDecimals={false} />
              <YAxis dataKey="zone" type="category" tick={{ fontSize: 11, fill: "#73726c" }} axisLine={false} tickLine={false} width={72} />
              <Tooltip formatter={(value) => [`${value}건`, "위반 수"]} labelFormatter={(label) => `Zone: ${label}`} />
              <Bar dataKey="count" fill="#0C447C" radius={[0, 4, 4, 0]} barSize={14} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div style={styles.card}>
        <div style={styles.tableHeader}>
          <h3 style={{ ...styles.chartTitle, margin: 0 }}>위반 목록</h3>
          <span style={styles.pageSummary}>
            {sorted.length ? `${(currentPage - 1) * PAGE_SIZE + 1}-${Math.min(currentPage * PAGE_SIZE, sorted.length)} / ${sorted.length}` : "0 / 0"}
          </span>
        </div>
        <div style={styles.filterRow}>
          {JUDGMENT_FILTERS.map((filter) => (
            <button
              key={filter.id}
              type="button"
              onClick={() => {
                setJudgmentFilter(filter.id);
                setPage(1);
              }}
              style={judgmentFilter === filter.id ? styles.filterButtonActive : styles.filterButton}
            >
              {filter.label}
              <span style={judgmentFilter === filter.id ? styles.filterCountActive : styles.filterCount}>
                {judgmentCounts[filter.id] ?? 0}
              </span>
            </button>
          ))}
        </div>
        <table style={styles.table}>
          <colgroup>
            <col style={styles.colId} />
            <col style={styles.colSource} />
            <col style={styles.colCategory} />
            <col style={styles.colContent} />
            <col style={styles.colSeverity} />
            <col style={styles.colStatus} />
            <col style={styles.colReason} />
            <col style={styles.colConfidence} />
            <col style={styles.colEvidence} />
            <col style={styles.colAction} />
          </colgroup>
          <thead>
            <tr>
              {["불변식 ID", "분류", "category", "불변식 내용", "위험도", "검증 상태", "사유", "신뢰도", "Evidence"].map((head, i) => (
                <th key={head} style={getViolationTableHeaderStyle(i)}>{head}</th>
              ))}
              <th style={styles.thSm}></th>
            </tr>
          </thead>
          <tbody>
            {pageItems.map((item) => {
              const invariant = invariantById[item.invariant_id];
              return (
                <tr key={item.result_id ?? item.invariant_id} style={styles.row}>
                  <td style={{ ...styles.td, ...styles.invariantIdCell }}>{item.invariant_id}</td>
                  <td style={styles.tdSm}>{formatSourceLabel(item.invariant_source ?? invariant?.invariant_source ?? item.source)}</td>
                  <td style={styles.tdSm}>{formatCategory(item, invariant)}</td>
                  <td style={{ ...styles.td, ...styles.invariantContentCell }}>
                    <span style={styles.truncatedInvariantContent} title={displayInvariantContent(item, invariant)}>
                      {displayInvariantContent(item, invariant)}
                    </span>
                  </td>
                  <td style={{ ...styles.tdSm, ...styles.severityCell }}><Badge value={item.severity} /></td>
                  <td style={styles.tdSm}>{formatJudgmentStatus(item, invariant)}</td>
                  <td style={styles.tdSm}>{formatViolationReason(item.violation_reason ?? invariant?.violation_reason)}</td>
                  <td style={styles.tdSm}>{formatConfidence(item.confidence)}</td>
                  <td style={styles.tdSm}>
                    <EvidenceCountCell count={toList(item.evidence_ids).length} />
                  </td>
                  <td style={{ ...styles.td, textAlign: "right" }}>
                    <button style={styles.linkButton} onClick={() => onOpenEvidence && onOpenEvidence(item, invariant)}>분석</button>
                  </td>
                </tr>
              );
            })}
            {sorted.length > 0 && Array.from({ length: PAGE_SIZE - pageItems.length }, (_, i) => (
              <tr key={`ghost-${i}`} aria-hidden="true">
                <td colSpan={10} style={{ ...styles.td, color: "transparent", userSelect: "none", pointerEvents: "none" }}>&nbsp;</td>
              </tr>
            ))}
            {!sorted.length && <EmptyRow colSpan={10} text="불변식 위반 항목이 없습니다." />}
          </tbody>
        </table>
        <Pagination page={currentPage} totalPages={totalPages} onPageChange={setPage} />
      </div>
    </section>
  );
}

function Pagination({ page, totalPages, onPageChange }) {
  if (totalPages <= 1) return null;
  const visiblePages = getVisiblePages(page, totalPages);
  return (
    <div style={styles.pagination}>
      <button type="button" onClick={() => onPageChange(Math.max(1, page - 1))} disabled={page <= 1} style={pageButton(false, page <= 1)}>‹</button>
      {visiblePages.map((pageNumber) => (
        <button key={pageNumber} type="button" onClick={() => onPageChange(pageNumber)} style={pageButton(page === pageNumber)}>
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

function EvidenceCountCell({ count }) {
  if (!count) return <span style={{ color: "#b0aea8", fontSize: 11 }}>-</span>;
  return <span style={{ fontSize: 12, color: "#374151" }}>{count}건</span>;
}

function ViolationRateBar({ label, violated, total }) {
  const pct = total === 0 ? 0 : Math.round((violated / total) * 100);
  return (
    <div style={styles.rateItem}>
      <div style={styles.rateHeader}>
        <span>{label}</span>
        <strong>{pct}% ({violated}/{total})</strong>
      </div>
      <div style={styles.rateTrack}>
        <div style={{ ...styles.rateFill, width: `${pct}%` }} />
      </div>
    </div>
  );
}

function formatConfidence(value) {
  if (typeof value !== "number") return "-";
  return `${Math.round(value * 100)}%`;
}

function normalizeConfidence(value) {
  if (typeof value === "number") return value > 1 ? value / 100 : value;
  const parsed = Number.parseFloat(value);
  if (Number.isNaN(parsed)) return 0;
  return parsed > 1 ? parsed / 100 : parsed;
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

function getJudgmentKey(violation, invariant) {
  return classifyInvariantJudgment({ ...(invariant ?? {}), ...violation });
}

function calcJudgmentFilterCounts(list) {
  const countsByJudgment = buildInvariantJudgmentCounts(
    list.filter((item) => item.__row_type === "invariant"),
    list.filter((item) => item.__row_type !== "invariant")
  );
  const counts = {
    all: list.length,
    confirmedViolation: countsByJudgment.confirmedViolation,
    unverifiable: countsByJudgment.unverifiable,
    normalOrNotObserved: countsByJudgment.normalOrNotObserved,
  };
  return counts;
}

function formatJudgmentStatus(violation, invariant) {
  const judgment = getJudgmentKey(violation, invariant);
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

function toList(value) {
  if (Array.isArray(value)) return value.filter(Boolean);
  return value ? [value] : [];
}

function buildInvariantMap(invariants) {
  return Object.fromEntries(
    invariants
      .map((invariant) => [invariant.invariant_id ?? invariant.id, invariant])
      .filter(([id]) => id)
  );
}

function buildJudgmentRows(invariants, violations) {
  const byId = new Map();
  invariants.forEach((item) => {
    const id = item.invariant_id ?? item.id;
    if (!id) return;
    byId.set(id, { ...item, invariant_id: id, __row_type: "invariant" });
  });
  violations.forEach((item) => {
    const id = item.invariant_id ?? item.id;
    if (!id) return;
    byId.set(id, { ...(byId.get(id) ?? {}), ...item, invariant_id: id, __row_type: "violation" });
  });
  return [...byId.values()];
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

function calcSourceRateStats(rows, invariants) {
  const sourceById = new Map(invariants.map((inv) => [inv.invariant_id ?? inv.id, getInvariantSource(inv)]));
  const rowSource = (row) => sourceById.get(row.invariant_id) ?? getInvariantSource(row);
  const totalFixed = invariants.filter((inv) => getInvariantSource(inv) === "fixed").length;
  const totalVariable = invariants.filter((inv) => getInvariantSource(inv) === "custom").length;
  const totalAll = invariants.length;
  const violatedFixed = rows.filter((v) => rowSource(v) === "fixed" && classifyInvariantJudgment(v) === "confirmedViolation").length;
  const violatedVariable = rows.filter((v) => rowSource(v) === "custom" && classifyInvariantJudgment(v) === "confirmedViolation").length;
  const violatedAll = rows.filter((v) => classifyInvariantJudgment(v) === "confirmedViolation").length;

  return [
    { label: "고정 불변식", violated: violatedFixed, total: totalFixed },
    { label: "가변 불변식", violated: violatedVariable, total: totalVariable },
    { label: "전체", violated: violatedAll, total: totalAll },
  ];
}

function calcSeverityDist(list) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  list.forEach((item) => {
    if (counts[item.severity] !== undefined) counts[item.severity] += 1;
  });
  return Object.entries(counts)
    .filter(([, value]) => value > 0)
    .map(([name, value]) => ({ name, value, color: SEVERITY_CHART_COLOR[name] }));
}

function calcZoneDist(list, assets = []) {
  const zoneViolationKeys = {};
  const assetById = buildAssetMap(assets);
  list.forEach((item, index) => {
    const violationKey = getViolationCountKey(item, index);
    const zones = getViolationAssetZones(item, assetById);
    zones.forEach((zone) => {
      if (!zoneViolationKeys[zone]) zoneViolationKeys[zone] = new Set();
      zoneViolationKeys[zone].add(violationKey);
    });
  });
  return Object.entries(zoneViolationKeys)
    .map(([zone, violationKeys]) => ({ zone, count: violationKeys.size }))
    .sort((a, b) => b.count - a.count);
}

function getViolationCountKey(violation, index) {
  const explicitId = violation.result_id ?? violation.violation_id ?? violation.id;
  if (explicitId) return explicitId;
  const assetIds = getViolationAssetIds(violation).join("|");
  const evidenceIds = toList(violation.evidence_ids).join("|");
  return [violation.invariant_id, assetIds, evidenceIds, violation.violation_reason ?? violation.reason, index].filter(Boolean).join("::");
}

function getViolationAssetZones(violation, assetById) {
  const relatedAssetIds = getViolationAssetIds(violation);
  const zonesFromAssets = relatedAssetIds
    .flatMap((assetId) => getAssetZoneCandidates(assetById[assetId]))
    .map(formatServerZone)
    .filter(Boolean);
  if (zonesFromAssets.length) return [...new Set(zonesFromAssets)];

  const inlineAssetZones = getInlineAffectedAssets(violation).flatMap(getAssetZoneCandidates).map(formatServerZone).filter(Boolean);
  if (inlineAssetZones.length) return [...new Set(inlineAssetZones)];

  return formatServerZones(violation.affected_zones);
}

function getViolationAssetIds(violation) {
  return uniqueList(
    violation.affected_registry_asset_ids,
    violation.asset_ids,
    violation.affected_asset_ids,
    violation.invariant_impact?.affected_registry_asset_ids,
    violation.invariant_impact?.asset_ids,
    getInlineAffectedAssets(violation).map((asset) => getAssetId(asset))
  );
}

function getInlineAffectedAssets(violation) {
  return [
    ...toList(violation.affected_assets),
    ...toList(violation.assets),
    ...toList(violation.invariant_impact?.affected_assets),
  ].filter((asset) => asset && typeof asset === "object");
}

function buildAssetMap(assets) {
  const pairs = [];
  toList(assets).forEach((asset) => {
    const ids = uniqueList(asset.asset_id, asset.id, asset.name, asset.asset_name, asset.vm, asset.hostname, asset.resource_id);
    ids.forEach((id) => pairs.push([id, asset]));
  });
  return Object.fromEntries(pairs);
}

function getAssetId(asset) {
  if (!asset || typeof asset !== "object") return asset;
  return asset.asset_id ?? asset.id ?? asset.name ?? asset.asset_name ?? asset.vm ?? asset.hostname ?? asset.resource_id;
}

function getAssetZoneCandidates(asset) {
  if (!asset || typeof asset !== "object") return [];
  return [asset.zone, asset.server_zone, asset.default_zone, asset.producer_zone, asset.primary_zone, asset.network_zone];
}

function uniqueList(...values) {
  return [...new Set(values.flatMap((value) => toList(value)).filter(Boolean))];
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

function getViolationTableHeaderStyle(index) {
  if (index === 0 || index === 3) return styles.th;
  return styles.thSm;
}

const styles = {
  rateCard: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: 16, minHeight: 276 },
  rateItem: { marginBottom: 14 },
  rateHeader: { display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 12, marginBottom: 5, color: "#1a1a18", fontWeight: 500 },
  rateTrack: { height: 8, background: "#E6F1FB", borderRadius: 999, overflow: "hidden" },
  rateFill: { height: "100%", background: "#0C447C", borderRadius: 999, transition: "width 0.3s" },
  chartGrid: { display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 14, marginBottom: 26 },
  chartCard: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: 16, minHeight: 276 },
  chartTitle: { margin: "0 0 10px", fontSize: 13, fontWeight: 700, color: "#1a1a18" },
  legendRow: { display: "flex", flexWrap: "wrap", gap: 10, marginTop: 2, minHeight: 18 },
  legendItem: { display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11, color: "#667085" },
  legendSwatch: { width: 10, height: 10, borderRadius: 2, display: "inline-block" },
  emptyChartText: { fontSize: 12, color: "#98a2b3" },
  card: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, overflow: "hidden", marginBottom: 22, padding: "10px 18px 16px" },
  tableHeader: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, gap: 12 },
  filterRow: { display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8, marginBottom: 12 },
  filterButton: { display: "inline-flex", alignItems: "center", gap: 7, border: "0.5px solid rgba(0,0,0,0.12)", background: "#fff", color: "#667085", borderRadius: 999, padding: "6px 10px", fontSize: 11, fontWeight: 700, cursor: "pointer" },
  filterButtonActive: { display: "inline-flex", alignItems: "center", gap: 7, border: "0.5px solid #185FA5", background: "#185FA5", color: "#fff", borderRadius: 999, padding: "6px 10px", fontSize: 11, fontWeight: 800, cursor: "pointer" },
  filterCount: { display: "inline-flex", alignItems: "center", justifyContent: "center", minWidth: 18, height: 16, padding: "0 5px", borderRadius: 999, background: "#EEF2F6", color: "#667085", fontSize: 10, fontWeight: 800 },
  filterCountActive: { display: "inline-flex", alignItems: "center", justifyContent: "center", minWidth: 18, height: 16, padding: "0 5px", borderRadius: 999, background: "rgba(255,255,255,0.22)", color: "#fff", fontSize: 10, fontWeight: 900 },
  pageSummary: { fontSize: 11, color: "#667085", whiteSpace: "nowrap" },
  table: { width: "100%", borderCollapse: "collapse", tableLayout: "fixed", fontSize: 12 },
  colId: { width: 135 },
  colSource: { width: 72 },
  colCategory: { width: 84 },
  colContent: { width: "auto" },
  colSeverity: { width: 105 },
  colStatus: { width: 130 },
  colReason: { width: 168 },
  colConfidence: { width: 80 },
  colEvidence: { width: 82 },
  colAction: { width: 60 },
  th: { textAlign: "left", padding: "9px 10px", color: "#73726c", borderBottom: "0.5px solid rgba(0,0,0,0.1)", fontWeight: 500 },
  thSm: { textAlign: "left", padding: "9px 10px", color: "#73726c", borderBottom: "0.5px solid rgba(0,0,0,0.1)", fontWeight: 500 },
  td: { padding: "11px 10px", borderBottom: "0.5px solid rgba(0,0,0,0.08)", color: "#1a1a18", verticalAlign: "middle" },
  tdSm: { padding: "11px 10px", borderBottom: "0.5px solid rgba(0,0,0,0.08)", color: "#1a1a18", verticalAlign: "middle" },
  invariantIdCell: { color: "#111827", fontFamily: "monospace", fontWeight: 500 },
  invariantContentCell: { minWidth: 0 },
  severityCell: { minWidth: 0 },
  truncatedInvariantContent: { display: "block", width: "100%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  row: { background: "#fff" },
  linkButton: { border: "none", background: "transparent", color: "#185FA5", fontSize: 11, fontWeight: 700, cursor: "pointer", padding: 0 },
  pagination: { display: "flex", justifyContent: "center", alignItems: "center", gap: 6, marginTop: 14, flexWrap: "wrap" },
};
