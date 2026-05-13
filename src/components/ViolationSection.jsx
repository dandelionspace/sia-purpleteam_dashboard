import { useMemo, useState } from "react";
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, EmptyRow, SectionTitle } from "./common";
import { getInvariantSource, sourceMatches } from "../utils/invariantSource";
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

export default function ViolationSection({ violations = [], assets = [], invariants = [], activeFilter = "all", onOpenEvidence = null }) {
  const [page, setPage] = useState(1);
  const filtered = activeFilter === "all"
    ? violations
    : violations.filter((item) => sourceMatches(item.invariant_source ?? item.source, activeFilter));
  const sourceRateStats = calcSourceRateStats(violations, invariants);
  const severityDist = calcSeverityDist(filtered);
  const zoneDist = calcZoneDist(filtered, assets);
  const invariantById = useMemo(() => buildInvariantMap(invariants), [invariants]);
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
      <SectionTitle title="불변식 위반 현황" subtitle="AI 1 의 결과에 기반한 불변식 위반 현황" />
      <div style={styles.chartGrid}>
        <div style={styles.rateCard}>
          <h3 style={styles.chartTitle}>고정/가변 위반율</h3>
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
          <h3 style={styles.chartTitle}>서버존별 위반 수</h3>
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
        <table style={styles.table}>
          <colgroup>
            <col style={styles.colId} />
            <col style={styles.colContent} />
            <col style={styles.colSeverity} />
            <col style={styles.colReason} />
            <col style={styles.colConfidence} />
            <col style={styles.colZone} />
            <col style={styles.colSource} />
            <col style={styles.colEvidence} />
            <col style={styles.colAction} />
          </colgroup>
          <thead>
            <tr>
              {["불변식 ID", "불변식 내용", "심각도", "위반 상세", "신뢰도", "서버 존", "구분", "Evidence 수"].map((head, i) => (
                <th key={head} style={getViolationTableHeaderStyle(i)}>{head}</th>
              ))}
              <th style={styles.thSm}></th>
            </tr>
          </thead>
          <tbody>
            {pageItems.map((item) => (
              <tr key={item.result_id ?? item.invariant_id} style={styles.row}>
                <td style={{ ...styles.td, ...styles.invariantIdCell }}>{item.invariant_id}</td>
                <td style={{ ...styles.td, ...styles.invariantContentCell }}>
                  <span
                    style={styles.truncatedInvariantContent}
                    title={displayInvariantContent(item, invariantById[item.invariant_id])}
                  >
                    {displayInvariantContent(item, invariantById[item.invariant_id])}
                  </span>
                </td>
                <td style={{ ...styles.tdSm, ...styles.severityCell }}><Badge value={item.severity} /></td>
                <td style={styles.tdSm}>{formatViolationReason(item.violation_reason)}</td>
                <td style={styles.tdSm}>{formatConfidence(item.confidence)}</td>
                <td style={styles.tdSm}>{getViolationZones(item, invariantById[item.invariant_id]?.server_zone || invariantById[item.invariant_id]?.default_zone || invariantById[item.invariant_id]?.zone).join(", ") || "-"}</td>
                <td style={styles.tdSm}>{formatSourceLabel(item.invariant_source ?? item.source)}</td>
                <td style={styles.tdSm}>
                  <EvidenceCountCell
                    count={toList(item.evidence_ids).length}
                  />
                </td>
                <td style={{ ...styles.td, textAlign: "right" }}>
                  <button style={styles.linkButton} onClick={() => onOpenEvidence && onOpenEvidence(item, invariantById[item.invariant_id])}>위반 분석 →</button>
                </td>
              </tr>
            ))}
            {sorted.length > 0 && Array.from({ length: PAGE_SIZE - pageItems.length }, (_, i) => (
              <tr key={`ghost-${i}`} aria-hidden="true">
                <td colSpan={9} style={{ ...styles.td, color: "transparent", userSelect: "none", pointerEvents: "none" }}>&nbsp;</td>
              </tr>
            ))}
            {!sorted.length && <EmptyRow colSpan={9} text="불변식 위반 항목이 없습니다" />}
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

function ViolationDrawer({ violation, onClose }) {
  const trace = violation.ai1_trace ?? {};
  const evidenceIds = toList(violation.evidence_ids);
  const assetIds = toList(violation.affected_registry_asset_ids ?? violation.asset_ids);
  const affectedServices = toList(violation.affected_services);
  const affectedZones = formatServerZones(violation.affected_zones);
  const requiredEvidenceTypes = toList(trace.required_evidence_types);
  const matchedEvidenceIds = toList(trace.matched_evidence_ids);
  const fieldsChecked = toList(trace.fields_checked);
  const missingFields = toList(trace.missing_fields);

  return (
    <div style={styles.overlay} onClick={onClose}>
      <aside style={styles.drawer} onClick={(event) => event.stopPropagation()}>
        <div style={styles.drawerHeader}>
          <div>
            <p style={styles.drawerEyebrow}>불변식 위반 상세</p>
            <h2 style={styles.drawerTitle}>{violation.invariant_id}</h2>
            <p style={styles.drawerSubtitle}>{violation.description ?? "불변식 설명이 없습니다."}</p>
          </div>
          <button onClick={onClose} style={styles.closeButton} aria-label="닫기">×</button>
        </div>

        <div style={styles.drawerBadges}>
          <StatusPill status={violation.status} />
          <ReasonPill reason={violation.violation_reason} />
          <Badge value={violation.severity} />
        </div>

        <div style={styles.summaryPanel}>
          <p style={styles.panelLabel}>판단 요약</p>
          <p style={styles.summaryText}>{violation.summary ?? violation.reason ?? "No summary provided."}</p>
          <div style={styles.metricGrid}>
            <Metric label="신뢰도" value={formatConfidence(violation.confidence)} />
            <Metric label="서버 존" value={formatServerZone(violation.server_zone ?? violation.zone) || "-"} />
          </div>
        </div>

        <DrawerSection title="상세 판단">
          <InfoBlock title="Reason" value={violation.reason} />
          <InfoBlock title="위반 상세" value={formatViolationReason(violation.violation_reason)} />
          <InfoBlock title="Result ID" value={violation.result_id} />
          <InfoBlock title="Detected at" value={formatDateTime(violation.detected_at ?? violation.created_at)} />
        </DrawerSection>

        <DrawerSection title="Evidence / 자산 참조">
          <InfoBlock title="Evidence IDs" value={<ChipGroup values={evidenceIds} tone="blue" />} />
          <InfoBlock title="Affected assets" value={<ChipGroup values={assetIds} />} />
          <InfoBlock title="Affected services" value={<ChipGroup values={affectedServices} />} />
          <InfoBlock title="Affected zones" value={<ChipGroup values={affectedZones} />} />
        </DrawerSection>

        <DrawerSection title="AI1 Trace">
          <InfoBlock title="Required evidence types" value={<ChipGroup values={requiredEvidenceTypes} tone="blue" />} />
          <InfoBlock title="Matched evidence IDs" value={<ChipGroup values={matchedEvidenceIds} tone="blue" />} />
          <InfoBlock title="Fields checked" value={<ChipGroup values={fieldsChecked} />} />
          <InfoBlock title="Decision basis" value={trace.decision_basis} />
          <InfoBlock title="Missing fields" value={missingFields.length ? <ChipGroup values={missingFields} tone="warn" /> : "None"} />
        </DrawerSection>

        <DrawerSection title="검증 가능성">
          <InfoBlock title="Current environment testable" value={formatTestable(violation.current_environment_testable)} />
          <InfoBlock title="Testability reason" value={violation.testability_reason} />
        </DrawerSection>

        {(violation.remediation || violation.priority) && (
          <div style={styles.remediationPanel}>
            <p style={styles.panelLabel}>권고 조치 {violation.priority ? `(${violation.priority})` : ""}</p>
            <p style={styles.summaryText}>{violation.remediation ?? "-"}</p>
          </div>
        )}
      </aside>
    </div>
  );
}

void ViolationDrawer;

function EvidenceCountCell({ count, onOpen }) {
  if (!count) return <span style={{ color: "#b0aea8", fontSize: 11 }}>-</span>;
  if (!onOpen) return <span style={{ fontSize: 12, color: "#374151" }}>{count}건</span>;
  return (
    <button style={styles.evidenceCountButton} onClick={onOpen}>
      {count}건
    </button>
  );
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

function DrawerSection({ title, children }) {
  return (
    <section style={styles.drawerSection}>
      <h3 style={styles.drawerSectionTitle}>{title}</h3>
      {children}
    </section>
  );
}

function InfoBlock({ title, value, mono = false }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div style={styles.infoBlock}>
      <strong style={styles.infoTitle}>{title}</strong>
      {typeof value === "string" || typeof value === "number" || typeof value === "boolean" ? (
        <p style={mono ? styles.monoInfoText : styles.infoText}>{value}</p>
      ) : value}
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div style={styles.metricItem}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function StatusPill({ status }) {
  const violated = status === "violated";
  return (
    <span style={{
      ...styles.drawerPill,
      background: violated ? "#FEF1F1" : "#F0FDF9",
      color: violated ? "#C53030" : "#276749",
    }}>
      {formatViolationStatus(status)}
    </span>
  );
}

function ReasonPill({ reason }) {
  const styleByReason = {
    clear_violation: { background: "#E6F1FB", color: "#0C447C" },
    partial_satisfaction: { background: "#EEF4FD", color: "#185FA5" },
    evidence_missing: { background: "#FEF3C7", color: "#92400E" },
    control_not_observed: { background: "#f1efea", color: "#73726c" },
  };
  return (
    <span style={{ ...styles.drawerPill, ...(styleByReason[reason] ?? { background: "#f1efea", color: "#73726c" }) }}>
      {formatViolationReason(reason)}
    </span>
  );
}

function ConfidencePill({ value }) {
  return (
    <span style={{ ...styles.drawerPill, background: "#F5F5F3", color: "#475569" }}>
      신뢰도 {formatConfidence(value)}
    </span>
  );
}

function ChipGroup({ values, tone = "gray" }) {
  const items = toList(values);
  if (!items.length) return <span style={styles.emptyInline}>-</span>;
  const color = tone === "blue"
    ? { background: "#F0F6FE", color: "#185FA5", border: "#c8ddf0" }
    : tone === "warn"
      ? { background: "#FEF3C7", color: "#92400E", border: "#FDE68A" }
      : { background: "#F5F5F3", color: "#73726c", border: "#e6e3dc" };
  return (
    <div style={styles.chipWrap}>
      {items.map((item) => (
        <span key={item} style={{ ...styles.detailChip, background: color.background, color: color.color, borderColor: color.border }}>
          {item}
        </span>
      ))}
    </div>
  );
}

function EvidenceSummaryList({ values }) {
  const items = toList(values);
  if (!items.length) return <span style={styles.emptyInline}>-</span>;
  return (
    <div style={styles.evidenceList}>
      {items.slice(0, 8).map((item, index) => (
        <div key={item.evidence_id ?? item.id ?? index} style={styles.evidenceItem}>
          <strong style={styles.evidenceTitle}>{item.evidence_id ?? item.id ?? `Evidence ${index + 1}`}</strong>
          <p style={styles.evidenceMeta}>
            {[
              item.evidence_type ?? item.event_type,
              item.producer?.vm ?? item.producer_vm,
              formatServerZone(item.producer?.zone ?? item.producer_zone),
              formatDateTime(item.collected_at ?? item.timestamp),
            ].filter(Boolean).join(" · ")}
          </p>
          <p style={styles.evidenceText}>{item.summary ?? item.name ?? item.reason ?? "-"}</p>
        </div>
      ))}
      {items.length > 8 && <span style={styles.emptyInline}>외 {items.length - 8}개 증거 요약</span>}
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

function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("ko-KR", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatTestable(value) {
  if (value === true) return "현재 환경 검증 가능";
  if (value === false) return "추가 환경 또는 수집 보강 필요";
  return "-";
}

function formatSourceLabel(value) {
  const source = getInvariantSource({ source: value });
  if (source === "fixed") return "고정 불변식";
  if (source === "custom") return "가변 불변식";
  return value ?? "-";
}

function formatViolationStatus(value) {
  return value === "violated" ? "위반" : "통과";
}

function formatViolationReason(value) {
  const labels = {
    clear_violation: "명백한 위반",
    partial_satisfaction: "부분 충족",
    evidence_missing: "증거 불충분",
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

function calcSourceRateStats(violations, invariants) {
  // invariants 카탈로그 기준으로 invariant_id → source 매핑
  const sourceById = new Map(
    invariants.map((inv) => [inv.invariant_id ?? inv.id, getInvariantSource(inv)])
  );
  const vSource = (v) => sourceById.get(v.invariant_id) ?? getInvariantSource(v);
  /*

  // 분모: 불변식 카탈로그 전체 수
  const totalFixed    = invariants.filter((inv) => (inv.invariant_source ?? inv.source) === "fixed").length;
  */
  const totalFixed    = invariants.filter((inv) => getInvariantSource(inv) === "fixed").length;
  const totalVariable = invariants.filter((inv) => getInvariantSource(inv) === "custom").length;
  const totalAll      = invariants.length;

  // 분자: violations 중 status === "violated"인 것 (source는 카탈로그 기준으로 해소)
  const violatedFixed    = violations.filter((v) => vSource(v) === "fixed"  && v.status === "violated").length;
  const violatedVariable = violations.filter((v) => vSource(v) === "custom" && v.status === "violated").length;
  const violatedAll      = violations.filter((v) => v.status === "violated").length;

  return [
    { label: "고정 불변식", violated: violatedFixed,    total: totalFixed },
    { label: "가변 불변식", violated: violatedVariable, total: totalVariable },
    { label: "전체",       violated: violatedAll,      total: totalAll },
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
  return [
    violation.invariant_id,
    assetIds,
    evidenceIds,
    violation.violation_reason ?? violation.reason,
    index,
  ].filter(Boolean).join("::");
}

function getViolationAssetZones(violation, assetById) {
  const relatedAssetIds = getViolationAssetIds(violation);
  const zonesFromAssets = relatedAssetIds
    .flatMap((assetId) => getAssetZoneCandidates(assetById[assetId]))
    .map(formatServerZone)
    .filter(Boolean);
  if (zonesFromAssets.length) return [...new Set(zonesFromAssets)];

  const inlineAssetZones = getInlineAffectedAssets(violation)
    .flatMap(getAssetZoneCandidates)
    .map(formatServerZone)
    .filter(Boolean);
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
    const ids = uniqueList(
      asset.asset_id,
      asset.id,
      asset.name,
      asset.asset_name,
      asset.vm,
      asset.hostname,
      asset.resource_id
    );
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
  return [
    asset.zone,
    asset.server_zone,
    asset.default_zone,
    asset.producer_zone,
    asset.primary_zone,
    asset.network_zone,
  ];
}

function getViolationZones(violation, invariantZone) {
  const zones = formatServerZones(violation.affected_zones);
  if (zones.length) return [...new Set(zones)];

  // ?? 대신 || 사용: 빈 문자열 ""도 falsy로 처리해 다음 fallback으로 넘어가야 함
  const fallback = formatServerZone(
    violation.server_zone || violation.zone || violation.default_zone || invariantZone
  );
  return fallback ? [fallback] : [];
}

function buildInvariantServerZoneMap(invariants) {
  return Object.fromEntries(
    invariants
      .map((invariant) => [
        invariant.invariant_id ?? invariant.id,
        invariant.server_zone || invariant.default_zone || invariant.zone,
      ])
      .filter(([invariantId, zone]) => invariantId && zone)
  );
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
  if (index === 0 || index === 1) return styles.th;
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
  pageSummary: { fontSize: 11, color: "#667085", whiteSpace: "nowrap" },
  table: { width: "100%", borderCollapse: "collapse", tableLayout: "fixed", fontSize: 12 },
  colId: { width: 135 },
  colContent: { width: "auto" },
  colSeverity: { width: 115 },
  colReason: { width: 160 },
  colConfidence: { width: 105 },
  colZone: { width: 220 },
  colSource: { width: 180 },
  colEvidence: { width: 90 },
  colAction: { width: 72 },
  th: { textAlign: "left", padding: "9px 10px", color: "#73726c", borderBottom: "0.5px solid rgba(0,0,0,0.1)", fontWeight: 500 },
  thSm: { textAlign: "left", padding: "9px 10px", color: "#73726c", borderBottom: "0.5px solid rgba(0,0,0,0.1)", fontWeight: 500 },
  td: { padding: "11px 10px", borderBottom: "0.5px solid rgba(0,0,0,0.08)", color: "#1a1a18", verticalAlign: "middle" },
  tdSm: { padding: "11px 10px", borderBottom: "0.5px solid rgba(0,0,0,0.08)", color: "#1a1a18", verticalAlign: "middle" },
  tdMono: { padding: "9px 10px", borderBottom: "0.5px solid rgba(0,0,0,0.08)", color: "#111827", fontFamily: "monospace", fontWeight: 500 },
  invariantIdCell: { color: "#111827", fontFamily: "monospace", fontWeight: 500, paddingRight: 24 },
  invariantContentCell: { minWidth: 0, paddingLeft: 24, paddingRight: 24 },
  severityCell: { paddingLeft: 24 },
  truncatedInvariantContent: { display: "block", width: "100%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  row: { background: "#fff" },
  linkButton: { border: "none", background: "transparent", color: "#185FA5", fontSize: 11, fontWeight: 700, cursor: "pointer", padding: 0 },
  evidenceCountButton: { border: "0.5px solid #c8ddf0", borderRadius: 6, background: "#EEF4FD", color: "#185FA5", fontSize: 11, fontWeight: 700, cursor: "pointer", padding: "3px 8px" },
  pagination: { display: "flex", justifyContent: "center", alignItems: "center", gap: 6, marginTop: 14, flexWrap: "wrap" },
  overlay: { position: "fixed", inset: 0, zIndex: 50, background: "rgba(0,0,0,0.15)", display: "flex", justifyContent: "flex-end" },
  drawer: { width: 560, maxWidth: "100vw", background: "#fff", height: "100%", overflowY: "auto", padding: "0 0 24px", boxShadow: "-4px 0 24px rgba(0,0,0,0.08)" },
  drawerHeader: { position: "sticky", top: 0, zIndex: 1, background: "#fff", display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16, padding: "20px 24px 16px", borderBottom: "0.5px solid rgba(0,0,0,0.08)" },
  closeButton: { width: 32, height: 32, flexShrink: 0, border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 8, background: "#fff", color: "#73726c", fontSize: 20, lineHeight: "28px", fontWeight: 500, padding: 0, cursor: "pointer" },
  drawerEyebrow: { margin: "0 0 4px", fontSize: 10, color: "#73726c", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 },
  drawerTitle: { margin: "0 0 6px", fontSize: 18, color: "#0C447C", fontWeight: 800 },
  drawerSubtitle: { margin: 0, fontSize: 12, color: "#1a1a18", lineHeight: 1.5 },
  drawerBadges: { display: "flex", flexWrap: "wrap", gap: 6, padding: "14px 24px 0" },
  drawerPill: { display: "inline-flex", alignItems: "center", minHeight: 22, padding: "2px 8px", borderRadius: 999, fontSize: 10, fontWeight: 700 },
  summaryPanel: { background: "#F8FAFC", border: "0.5px solid rgba(0,0,0,0.08)", borderRadius: 10, padding: 14, margin: "14px 24px 16px" },
  remediationPanel: { background: "#E6F1FB", borderRadius: 10, padding: 14, margin: "16px 24px 0" },
  panelLabel: { margin: "0 0 8px", fontSize: 10, color: "#73726c", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 700 },
  summaryText: { margin: 0, fontSize: 12, lineHeight: 1.65, color: "#1a1a18" },
  metricGrid: { display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 8, marginTop: 14 },
  metricItem: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.08)", borderRadius: 8, padding: "9px 10px", display: "flex", flexDirection: "column", gap: 3, minWidth: 0 },
  drawerSection: { margin: "0 24px", borderTop: "0.5px solid rgba(0,0,0,0.08)", padding: "14px 0 2px" },
  drawerSectionTitle: { margin: "0 0 8px", fontSize: 12, color: "#1a1a18", fontWeight: 800 },
  infoBlock: { padding: "8px 0", fontSize: 12, lineHeight: 1.55, color: "#1a1a18" },
  infoTitle: { display: "block", marginBottom: 4, fontSize: 10, color: "#73726c", fontWeight: 700 },
  infoText: { margin: 0, fontSize: 12, lineHeight: 1.6, color: "#1a1a18" },
  monoInfoText: { margin: 0, fontSize: 11, lineHeight: 1.6, color: "#475569", fontFamily: "monospace", wordBreak: "break-all" },
  chipWrap: { display: "flex", flexWrap: "wrap", gap: 5 },
  detailChip: { display: "inline-flex", alignItems: "center", minHeight: 20, padding: "1px 7px", borderRadius: 999, border: "0.5px solid", fontSize: 10, fontWeight: 600 },
  evidenceList: { display: "grid", gap: 8 },
  evidenceItem: { border: "0.5px solid rgba(0,0,0,0.08)", borderRadius: 8, padding: "8px 10px", background: "#fff" },
  evidenceTitle: { display: "block", marginBottom: 3, fontSize: 11, color: "#185FA5", fontFamily: "monospace" },
  evidenceMeta: { margin: "0 0 3px", fontSize: 10, color: "#73726c", lineHeight: 1.45 },
  evidenceText: { margin: 0, fontSize: 11, color: "#1a1a18", lineHeight: 1.5 },
  emptyInline: { color: "#b0aea8", fontSize: 11 },
};
