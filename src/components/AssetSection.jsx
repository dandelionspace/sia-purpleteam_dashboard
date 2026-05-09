import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useState } from "react";
import { ChipList, EmptyRow, SectionTitle } from "./common";

const PAGE_SIZE = 10;

export default function AssetSection({ assets = [], assetChanges = [], assetReviewQueue = [], invariantImpact = [], evidenceEvents = [], assetHistory = [] }) {
  return (
    <section>
      <SectionTitle title="자산 목록과 evidence 영향 " subtitle="스캔 상세 데이터에서 자산, Evidence, 불변식 영향 관계 추적" />
      <Summary assets={assets} assetChanges={assetChanges} assetReviewQueue={assetReviewQueue} />
      <Timeline assetHistory={assetHistory} />
      <AssetTable assets={assets} invariantImpact={invariantImpact} />
      <ChangeQueue assetChanges={assetChanges} assetReviewQueue={assetReviewQueue} />
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
  const [selectedPoint, setSelectedPoint] = useState(assetHistory.at(-1) ?? null);
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
            <Tooltip />
            <Line dataKey="total" name="Assets" stroke="#2f6fed" strokeWidth={2} activeDot={{ onClick: (_, payload) => setSelectedPoint(payload?.payload) }} />
            <Line dataKey="with_violation" name="Violated invariants" stroke="#d92d20" strokeWidth={2} activeDot={{ onClick: (_, payload) => setSelectedPoint(payload?.payload) }} />
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
            <Tooltip />
            <Bar dataKey="changed_assets" name="Changed assets" fill="#2f6fed" />
            <Bar dataKey="new_violations" name="New violations" fill="#d92d20" />
            <Bar dataKey="resolved" name="Resolved" fill="#12b76a" />
          </BarChart>
        </ResponsiveContainer>
        {selectedPoint && (
          <div style={styles.drilldown}>
            <strong>{selectedPoint.scan_id ?? selectedPoint.date}</strong>
            <DetailChips label="Changed assets" values={selectedPoint.changed_asset_ids} />
            <DetailChips label="Violated invariants" values={selectedPoint.violated_invariants} />
            <DetailChips label="New violations" values={selectedPoint.new_violations_since_previous_run} />
            <DetailChips label="Resolved invariants" values={selectedPoint.resolved_invariants_since_previous_run} />
          </div>
        )}
      </div>
    </div>
  );
}

function DetailChips({ label, values = [] }) {
  return (
    <div style={styles.detailChips}>
      <span>{label}</span>
      <ChipList values={values} />
    </div>
  );
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
  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle}>{title}</h3>
      {items.length ? items.map((item) => (
        <div key={`${item[idKey]}-${item[textKey]}`} style={styles.listItem}>
          <strong>{item[idKey]}</strong>
          <span>{item[textKey]}</span>
          {item.evidence_ids?.length ? <ChipList values={item.evidence_ids} /> : null}
        </div>
      )) : <p style={styles.emptyText}>None</p>}
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
  return (
    <div style={styles.pagination}>
      {Array.from({ length: totalPages }, (_, index) => index + 1).map((pageNumber) => (
        <button
          key={pageNumber}
          onClick={() => onPageChange(pageNumber)}
          style={pageButton(page === pageNumber)}
        >
          {pageNumber}
        </button>
      ))}
    </div>
  );
}

function paginate(items, page) {
  const totalPages = Math.max(1, Math.ceil(items.length / PAGE_SIZE));
  const currentPage = Math.min(Math.max(page, 1), totalPages);
  const start = (currentPage - 1) * PAGE_SIZE;
  return {
    pageItems: items.slice(start, start + PAGE_SIZE),
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
  drilldown: { marginTop: 12, borderTop: "1px solid #eef2f6", paddingTop: 10, display: "grid", gap: 8, fontSize: 12 },
  detailChips: { display: "grid", gridTemplateColumns: "140px 1fr", gap: 8, alignItems: "start", color: "#667085" },
  pagination: { display: "flex", justifyContent: "center", alignItems: "center", gap: 6, marginTop: 14, flexWrap: "wrap" },
};

function pageButton(active) {
  return {
    minWidth: 30,
    height: 30,
    border: `1px solid ${active ? "#185FA5" : "#e4e7ec"}`,
    borderRadius: 6,
    background: active ? "#185FA5" : "#fff",
    color: active ? "#fff" : "#667085",
    fontSize: 12,
    fontWeight: active ? 700 : 500,
    cursor: "pointer",
  };
}
