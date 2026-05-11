import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useState } from "react";
import { ChipList, EmptyRow, SectionTitle } from "./common";

const PAGE_SIZE = 10;
const LIST_PAGE_SIZE = 10;
const MAX_PAGE_BUTTONS = 10;

export default function AssetSection({ assets = [], assetChanges = [], assetReviewQueue = [], invariantImpact = [], evidenceEvents = [], assetHistory = [], assetEvents = [], assetHistoryMonthly = [] }) {
  return (
    <section>
      <SectionTitle title="자산 목록과 evidence 영향 " subtitle="스캔 상세 데이터에서 자산, Evidence, 불변식 영향 관계 추적" />
      <Summary assets={assets} assetChanges={assetChanges} assetReviewQueue={assetReviewQueue} />
      <Timeline assetHistory={assetHistory} />
      <MonthlyTrendChart data={assetHistoryMonthly} />
      <AssetTable assets={assets} invariantImpact={invariantImpact} />
      <ChangeQueue assetChanges={assetChanges} assetReviewQueue={assetReviewQueue} />
      <AssetEventTable assetEvents={assetEvents} />
      <EvidenceTable evidenceEvents={evidenceEvents} />
    </section>
  );
}

function Summary({ assets, assetChanges, assetReviewQueue }) {
  const cards = [
    ["총 자산", assets.length],
    ["변경된 자산", assetChanges.length],
    ["Review queue", assetReviewQueue.length],
    ["불변식 위반 항목과 연결된 자산", assets.filter((asset) => asset.related_invariant_ids?.length).length],
  ];
  return (
    <div style={styles.summaryGrid}>
      {cards.map(([label, value]) => (
        <div key={label} style={styles.card}><span style={styles.label}>{label}</span><strong style={styles.value}>{value}</strong></div>
      ))}
    </div>
  );
}

function Timeline({ assetHistory }) {
  if (!assetHistory.length) return null;
  return (
    <div style={styles.chartGrid}>
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>Asset and violation timeline</h3>
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={assetHistory}>
            <CartesianGrid stroke="#eef2f6" />
            <XAxis dataKey="date" tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} />
            <Tooltip labelFormatter={formatTooltipLabel} />
            <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11 }} />
            <Line dataKey="total" name="전체 자산" stroke="#2f6fed" strokeWidth={2} />
            <Line dataKey="with_violation" name="위반 불변식" stroke="#d92d20" strokeWidth={2} />
          </LineChart>
        </ResponsiveContainer>
      </div>
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>Run drilldown deltas</h3>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={assetHistory}>
            <CartesianGrid stroke="#eef2f6" />
            <XAxis dataKey="date" tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} />
            <Tooltip labelFormatter={formatTooltipLabel} />
            <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11 }} />
            <Bar dataKey="changed_assets" name="변경 자산" fill="#2f6fed" />
            <Bar dataKey="new_violations" name="신규 위반" fill="#d92d20" />
            <Bar dataKey="resolved" name="해결된 불변식" fill="#12b76a" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function MonthlyTrendChart({ data }) {
  if (!data.length) return null;
  const chartData = data.map((row) => ({
    month: row.date_label ?? row.period_start,
    total: row.total ?? 0,
    vulnerable: row.vulnerable ?? 0,
    unregistered: row.unregistered ?? 0,
  }));
  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle}>월별 자산 추이</h3>
      <ResponsiveContainer width="100%" height={220}>
        <LineChart data={chartData}>
          <CartesianGrid stroke="#eef2f6" />
          <XAxis dataKey="month" tick={{ fontSize: 11 }} />
          <YAxis tick={{ fontSize: 11 }} />
          <Tooltip />
          <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11 }} />
          <Line dataKey="total" name="전체 자산" stroke="#2f6fed" strokeWidth={2} dot={{ r: 4 }} />
          <Line dataKey="vulnerable" name="위반 자산" stroke="#d92d20" strokeWidth={2} dot={{ r: 4 }} />
          <Line dataKey="unregistered" name="미등록 자산" stroke="#f79009" strokeWidth={2} dot={{ r: 4 }} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

const EVENT_TYPE_STYLE = {
  asset_updated:  { label: "자산 변경",    bg: "#FEF3C7", color: "#92400E" },
  asset_created:  { label: "신규 등록",    bg: "#D1FAE5", color: "#065F46" },
  asset_removed:  { label: "자산 삭제",    bg: "#FEE2E2", color: "#991B1B" },
  service_added:  { label: "서비스 추가",  bg: "#EDE9FE", color: "#5B21B6" },
  service_removed:{ label: "서비스 제거",  bg: "#FEE2E2", color: "#991B1B" },
};

function AssetEventTable({ assetEvents }) {
  const [page, setPage] = useState(1);
  const { pageItems, currentPage, totalPages } = paginate(assetEvents, page);
  if (!assetEvents.length) return null;
  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle}>자산 변경 이력</h3>
      <TableMeta total={assetEvents.length} currentPage={currentPage} totalPages={totalPages} />
      <table style={styles.table}>
        <thead>
          <tr>{["유형", "자산 ID", "Zone", "내용", "발생 시각", "심각도"].map((h) => <th key={h} style={styles.th}>{h}</th>)}</tr>
        </thead>
        <tbody>
          {pageItems.map((ev) => {
            const typeStyle = EVENT_TYPE_STYLE[ev.event_type] ?? { label: ev.event_type ?? "-", bg: "#F3F4F6", color: "#374151" };
            return (
              <tr key={ev.event_id}>
                <td style={styles.td}>
                  <span style={{ padding: "2px 8px", borderRadius: 999, fontSize: 11, fontWeight: 600, background: typeStyle.bg, color: typeStyle.color }}>
                    {typeStyle.label}
                  </span>
                </td>
                <td style={styles.tdMono}>{ev.asset_id ?? ev.asset_name ?? "-"}</td>
                <td style={styles.td}>{ev.zone ?? "-"}</td>
                <td style={{ ...styles.td, maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={ev.description}>{ev.description ?? "-"}</td>
                <td style={styles.td}>{formatDate(ev.occurred_at)}</td>
                <td style={styles.td}>{ev.severity ?? "-"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <Pagination page={currentPage} totalPages={totalPages} onPageChange={setPage} />
    </div>
  );
}

function formatTooltipLabel(label, payload = []) {
  return payload[0]?.payload?.tooltip_label ?? label;
}

function AssetTable({ assets, invariantImpact }) {
  const [page, setPage] = useState(1);
  const impactByAsset = groupBy(invariantImpact, "asset_id");
  const { pageItems, currentPage, totalPages } = paginate(assets, page);
  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle}>자산 목록 </h3>
      <TableMeta total={assets.length} currentPage={currentPage} totalPages={totalPages} />
      <table style={styles.table}>
        <thead><tr>{["자산 ID", "이름", "유형", "Zone", "Evidence", "연관 불변식"].map((head) => <th key={head} style={styles.th}>{head}</th>)}</tr></thead>
        <tbody>
          {pageItems.map((asset) => (
            <tr key={asset.asset_id}>
              <td style={styles.tdMono}>{asset.asset_id}</td>
              <td style={styles.td}>{asset.asset_name}</td>
              <td style={styles.td}>{asset.asset_type}</td>
              <td style={styles.td}>{asset.zone ?? asset.segment ?? "-"}</td>
              <td style={styles.td}><ChipList values={asset.evidence_ids} /></td>
              <td style={styles.td}><ChipList values={(impactByAsset[asset.asset_id] ?? []).map((item) => item.invariant_id)} /></td>
            </tr>
          ))}
          {!assets.length && <EmptyRow colSpan={6} text="자산이 없습니다" />}
        </tbody>
      </table>
      <Pagination page={currentPage} totalPages={totalPages} onPageChange={setPage} />
    </div>
  );
}

function ChangeQueue({ assetChanges, assetReviewQueue }) {
  return (
    <div style={styles.twoCol}>
      <ListCard title="변경된 자산" items={assetChanges} idKey="asset_id" textKey="summary" />
      <ListCard title="등록되지 않은 자산 검토 대기열" items={assetReviewQueue} idKey="asset_id" textKey="reason" />
    </div>
  );
}

function ListCard({ title, items, idKey, textKey }) {
  const [page, setPage] = useState(1);
  const { pageItems, currentPage, totalPages } = paginate(items, page, LIST_PAGE_SIZE);

  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle}>{title}</h3>
      <TableMeta total={items.length} currentPage={currentPage} totalPages={totalPages} />
      {items.length ? pageItems.map((item) => (
        <div key={`${item[idKey]}-${item[textKey]}`} style={styles.listItem}>
          <strong>{item[idKey]}</strong>
          <span>{item[textKey]}</span>
          {item.evidence_ids?.length ? <ChipList values={item.evidence_ids} /> : null}
        </div>
      )) : <p style={styles.emptyText}>None</p>}
      <Pagination page={currentPage} totalPages={totalPages} onPageChange={setPage} />
    </div>
  );
}

function EvidenceTable({ evidenceEvents }) {
  const [page, setPage] = useState(1);
  const { pageItems, currentPage, totalPages } = paginate(evidenceEvents, page);
  return (
    <div style={styles.card}>
      <TableMeta total={evidenceEvents.length} currentPage={currentPage} totalPages={totalPages} />
      <h3 style={styles.cardTitle}>evidence 목록</h3>
      <table style={styles.table}>
        <thead><tr>{["Evidence ID", "Type", "Collected", "Asset", "Trace", "Summary"].map((head) => <th key={head} style={styles.th}>{head}</th>)}</tr></thead>
        <tbody>
          {pageItems.map((event) => (
            <tr key={event.evidence_id}>
              <td style={styles.tdMono}>{event.evidence_id}</td>
              <td style={styles.td}>{event.evidence_type}</td>
              <td style={styles.td}>{formatDate(event.collected_at)}</td>
              <td style={styles.td}>{formatEvidenceAsset(event)}</td>
              <td style={styles.td}>{event.security_context?.trace_id ?? event.security_context?.request_id ?? "-"}</td>
              <td style={styles.td}>{formatEvidenceSummary(event)}</td>
            </tr>
          ))}
          {!evidenceEvents.length && <EmptyRow colSpan={6} text="evidence가 없습니다" />}
        </tbody>
      </table>
      <Pagination page={currentPage} totalPages={totalPages} onPageChange={setPage} />
    </div>
  );
}

function TableMeta({ total, currentPage, totalPages }) {
  return (
    <div style={styles.tableMeta}>
      <span>{total ? `${total} items · ${currentPage}/${totalPages}` : "0 items"}</span>
    </div>
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

function paginate(items, page, pageSize = PAGE_SIZE) {
  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
  const currentPage = Math.min(Math.max(page, 1), totalPages);
  const start = (currentPage - 1) * pageSize;
  return {
    pageItems: items.slice(start, start + pageSize),
    currentPage,
    totalPages,
  };
}

function formatEvidenceAsset(event) {
  return event.asset?.asset_id
    ?? event.asset_id
    ?? event.target_asset_id
    ?? event.target?.asset_id
    ?? event.producer_asset_id
    ?? event.producer?.asset_id
    ?? "-";
}

function formatEvidenceSummary(event) {
  const access = event.access ?? {};
  const accessText = [
    access.method,
    access.endpoint ?? access.action,
  ].filter(Boolean).join(" ");
  const result = access.authorization_decision ?? access.decision ?? access.status_code;
  if (accessText || result) return [accessText, result ? `-> ${result}` : ""].filter(Boolean).join(" ");

  const observed = event.observed ?? {};
  const observedEntries = Object.entries(observed)
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .slice(0, 3)
    .map(([key, value]) => `${key}=${String(value)}`);
  if (observedEntries.length) return observedEntries.join(", ");

  return event.summary ?? event.reason ?? "-";
}

function groupBy(items, key) {
  return items.reduce((acc, item) => {
    const value = item[key] ?? "unknown";
    acc[value] = acc[value] ?? [];
    acc[value].push(item);
    return acc;
  }, {});
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ko-KR");
}

const styles = {
  summaryGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginBottom: 12 },
  chartGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 12, marginBottom: 12 },
  twoCol: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 12 },
  card: { background: "#fff", border: "1px solid #e4e7ec", borderRadius: 8, padding: 16, marginBottom: 12 },
  label: { display: "block", color: "#667085", fontSize: 12, marginBottom: 7 },
  value: { fontSize: 26, color: "#173b70" },
  cardTitle: { margin: "0 0 12px", fontSize: 14 },
  tableMeta: { display: "flex", justifyContent: "flex-end", color: "#98a2b3", fontSize: 12, marginBottom: 8 },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 12 },
  th: { textAlign: "left", padding: "9px 10px", color: "#667085", borderBottom: "1px solid #e4e7ec" },
  td: { padding: "9px 10px", borderBottom: "1px solid #eef2f6", color: "#344054", verticalAlign: "top" },
  tdMono: { padding: "9px 10px", borderBottom: "1px solid #eef2f6", color: "#344054", fontWeight: 400 },
  listItem: { borderTop: "1px solid #eef2f6", padding: "10px 0", display: "flex", flexDirection: "column", gap: 5, color: "#344054", fontSize: 13 },
  emptyText: { margin: 0, color: "#98a2b3", fontSize: 13 },
  pagination: { display: "flex", justifyContent: "center", alignItems: "center", gap: 6, marginTop: 14, flexWrap: "wrap" },
};

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
