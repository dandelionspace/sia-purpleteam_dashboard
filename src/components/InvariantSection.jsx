import { useMemo, useState } from "react";
import { createInvariant } from "../services/scanService";
import { EmptyRow, SectionTitle } from "./common";

const STATES = ["active", "disabled", "draft"];
const SOURCES = ["fixed", "custom"];
const APPROVAL = ["approved", "draft"];
const PAGE_SIZE = 10;
const MAX_PAGE_BUTTONS = 10;

const FILTER_TABS = [
  { id: "all", label: "전체" },
  { id: "fixed", label: "고정" },
  { id: "variable", label: "가변" },
];

const VALUE_LABELS = {
  fixed: "고정 불변식",
  variable: "가변 불변식",
  custom: "가변 불변식",
  active: "활성",
  disabled: "비활성",
  draft: "승인 대기",
  approved: "승인 완료",
};

export default function InvariantSection({ invariants = [], readiness = [] }) {
  const [localInvariants, setLocalInvariants] = useState([]);
  const [deletedIds, setDeletedIds] = useState([]);
  const [selectedIds, setSelectedIds] = useState([]);
  const [form, setForm] = useState({ invariant_id: "", title: "", source: "custom", state: "draft", approval_status: "draft" });
  const [activeFilter, setActiveFilter] = useState("all");
  const [page, setPage] = useState(1);
  const displayedInvariants = useMemo(() => (
    mergeByInvariantId(invariants, localInvariants).filter((item) => !deletedIds.includes(invariantId(item)))
  ), [deletedIds, invariants, localInvariants]);
  const filteredInvariants = useMemo(
    () => displayedInvariants.filter((item) => sourceMatches(item.source ?? item.invariant_source, activeFilter)),
    [displayedInvariants, activeFilter]
  );
  const totalPages = Math.max(1, Math.ceil(filteredInvariants.length / PAGE_SIZE));
  const currentPage = Math.min(Math.max(page, 1), totalPages);
  const pageItems = filteredInvariants.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  const save = async () => {
    if (!form.invariant_id || !form.title) return;
    await createInvariant(form);
    setLocalInvariants((items) => upsert(items, form));
    setDeletedIds((ids) => ids.filter((id) => id !== form.invariant_id));
    setForm({ invariant_id: "", title: "", source: "custom", state: "draft", approval_status: "draft" });
  };

  const startEdit = (item) => {
    setForm({
      invariant_id: invariantId(item),
      title: displayTitle(item),
      source: item.source ?? item.invariant_source ?? "custom",
      state: item.state ?? (item.active === false ? "disabled" : "active"),
      approval_status: item.approval_status ?? item.catalog_status ?? "approved",
    });
  };

  const deleteSelected = () => {
    if (!selectedIds.length) return;
    setDeletedIds((ids) => [...new Set([...ids, ...selectedIds])]);
    setLocalInvariants((items) => items.filter((item) => !selectedIds.includes(invariantId(item))));
    setSelectedIds([]);
  };

  const toggleSelected = (id) => {
    setSelectedIds((ids) => ids.includes(id) ? ids.filter((item) => item !== id) : [...ids, id]);
  };

  const pageIds = pageItems.map(invariantId).filter(Boolean);
  const allPageSelected = pageIds.length > 0 && pageIds.every((id) => selectedIds.includes(id));
  const togglePageSelected = () => {
    setSelectedIds((ids) => {
      if (allPageSelected) return ids.filter((id) => !pageIds.includes(id));
      return [...new Set([...ids, ...pageIds])];
    });
  };

  return (
    <section>
      <SectionTitle title="불변식 목록" subtitle="새 불변식을 입력하면 목록에 저장되고 다음 AI Pack 실행에서 AI1의 평가 대상이 됩니다." />
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>불변식 추가 및 수정</h3>
        <div style={styles.formGrid}>
          <input style={styles.input} value={form.invariant_id} placeholder="INV-CUSTOM-01" onChange={(event) => setForm({ ...form, invariant_id: event.target.value })} />
          <input style={styles.input} value={form.title} placeholder="Invariant title" onChange={(event) => setForm({ ...form, title: event.target.value })} />
          <Select value={form.source} values={SOURCES} onChange={(source) => setForm({ ...form, source })} />
          <Select value={form.state} values={STATES} onChange={(state) => setForm({ ...form, state })} />
          <Select value={form.approval_status} values={APPROVAL} onChange={(approval_status) => setForm({ ...form, approval_status })} />
          <button style={styles.primaryButton} onClick={save}>저장</button>
          <button style={styles.secondaryButton} onClick={() => setForm({ invariant_id: "", title: "", source: "custom", state: "draft", approval_status: "draft" })}>초기화</button>
        </div>
        <p style={styles.formHint}>현재 API 문서에는 삭제/수정 전용 endpoint가 없어 화면 목록 기준으로 반영합니다. 저장은 기존 불변식 생성 API를 사용합니다.</p>
      </div>
      <div style={styles.card}>
        <div style={styles.tableHeader}>
          <div style={styles.filterRow}>
            {FILTER_TABS.map((tab) => {
              const count = displayedInvariants.filter((item) => sourceMatches(item.source ?? item.invariant_source, tab.id)).length;
              return (
                <button
                  key={tab.id}
                  type="button"
                  style={filterButton(activeFilter === tab.id)}
                  onClick={() => {
                    setActiveFilter(tab.id);
                    setPage(1);
                  }}
                >
                  {tab.label}
                  <span style={filterCount(activeFilter === tab.id)}>{count}</span>
                </button>
              );
            })}
          </div>
          <span style={styles.pageSummary}>
            {filteredInvariants.length ? `${(currentPage - 1) * PAGE_SIZE + 1}-${Math.min(currentPage * PAGE_SIZE, filteredInvariants.length)} / ${filteredInvariants.length}` : "0 / 0"}
          </span>
        </div>
        <table style={styles.table}>
          <thead>
            <tr>
              {["불변식 ID", "분류", "category", "불변식 내용", "위험도", "검증 상태", "사유", "활성 여부", "승인 상태", "Readiness", "수정"].map((head) => <th key={head} style={styles.th}>{head}</th>)}
            </tr>
          </thead>
          <tbody>
            {pageItems.map((item) => {
              const id = invariantId(item);
              const ready = readiness.find((row) => row.invariant_id === id);
              return (
                <tr key={id}>
                  <td style={styles.tdMono}>{id}</td>
                  <td style={styles.td}>{formatSource(item.source ?? item.invariant_source)}</td>
                  <td style={styles.td}>{formatCategory(item)}</td>
                  <td style={styles.td}>{displayTitle(item)}</td>
                  <td style={styles.td}>{formatRisk(item)}</td>
                  <td style={styles.td}>{formatEvaluationStatus(item)}</td>
                  <td style={styles.td}>{formatReason(item)}</td>
                  <td style={styles.td}>{formatActiveState(item)}</td>
                  <td style={styles.td}>{formatApprovalStatus(item)}</td>
                  <td style={styles.td}>{formatReadiness(ready)}</td>
                  <td style={styles.td}>
                    <button type="button" style={styles.linkButton} onClick={() => startEdit(item)}>수정</button>
                  </td>
                </tr>
              );
            })}
            {!filteredInvariants.length && <EmptyRow colSpan={11} text="No invariant catalog returned." />}
          </tbody>
        </table>
        <Pagination page={currentPage} totalPages={totalPages} onPageChange={setPage} />
      </div>
    </section>
  );
}

function Select({ value, values, onChange }) {
  return (
    <select style={styles.input} value={value} onChange={(event) => onChange(event.target.value)}>
      {values.map((item) => <option key={item} value={item}>{labelFor(item)}</option>)}
    </select>
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

function displayTitle(item) {
  const id = invariantId(item);
  const candidates = [item.title, item.name, item.catalog_title, item.description];
  return candidates.find((v) => v && v !== id) ?? "DB 항목이 비어있습니다.";
}

function invariantId(item = {}) {
  return item.invariant_id ?? item.id;
}

function labelFor(value) {
  return VALUE_LABELS[value] ?? value ?? "-";
}

function formatSource(value) {
  if (value === "fixed") return "고정";
  if (["custom", "variable"].includes(value)) return "가변";
  return value ?? "-";
}

function formatCategory(item) {
  return item.category ?? item.type ?? item.default_zone ?? "-";
}

function formatRisk(item) {
  return item.severity ?? item.risk_level ?? item.risk ?? "-";
}

function formatEvaluationStatus(item) {
  const value = item.evaluation_status ?? item.status ?? item.last_result_status;
  if (value === "violated") return "위반";
  if (value === "applied") return "적용";
  if (["not_testable", "unknown", "unverified", "미점검"].includes(value)) return "검증 불가";
  return value ?? "-";
}

function formatReason(item) {
  const value = item.violation_reason ?? item.last_violation_reason ?? item.reason ?? item.collector_gap_reason;
  const labels = {
    clear_violation: "조건값 위반",
    partial_satisfaction: "부분 충족",
    evidence_missing: "증거 부족",
    control_not_observed: "통제 미관측",
  };
  return labels[value] ?? value ?? "-";
}

function formatActiveState(item) {
  const state = item.state ?? (item.active === false ? "disabled" : "active");
  if (state === "active") return "활성";
  if (state === "disabled") return "비활성";
  if (state === "draft") return "초안";
  return state ?? "-";
}

function formatApprovalStatus(item) {
  const value = item.approval_status ?? item.catalog_status ?? item.approval_state;
  if (value === "approved") return "승인 완료";
  if (value === "draft") return "승인 대기";
  return value ?? "-";
}

function formatReadiness(ready) {
  return ready?.status ?? ready?.reason ?? "-";
}

function sourceMatches(source, filter) {
  if (filter === "all") return true;
  if (filter === "variable") return ["custom", "variable"].includes(source);
  return source === filter;
}

function upsert(items, item) {
  const id = invariantId(item);
  const index = items.findIndex((candidate) => invariantId(candidate) === id);
  if (index < 0) return [...items, item];
  const next = [...items];
  next[index] = item;
  return next;
}

function mergeByInvariantId(remote, local) {
  const map = new Map(remote.map((item) => [invariantId(item), item]));
  local.forEach((item) => map.set(invariantId(item), item));
  return [...map.values()];
}

const styles = {
  card: { background: "#fff", border: "1px solid #e4e7ec", borderRadius: 8, padding: 16, marginBottom: 12 },
  cardTitle: { margin: "0 0 12px", fontSize: 14 },
  formGrid: { display: "grid", gridTemplateColumns: "1fr 2fr repeat(3, minmax(120px, auto)) auto auto", gap: 8 },
  input: { border: "1px solid #d0d5dd", borderRadius: 7, padding: "8px 10px", fontSize: 13, fontFamily: "inherit", minWidth: 0 },
  primaryButton: { border: "none", background: "#2f6fed", color: "#fff", borderRadius: 7, padding: "8px 12px", fontWeight: 700, cursor: "pointer" },
  secondaryButton: { border: "1px solid #d0d5dd", background: "#fff", color: "#344054", borderRadius: 7, padding: "8px 12px", fontWeight: 700, cursor: "pointer" },
  dangerButton: { border: "1px solid #FECACA", background: "#FEF1F1", color: "#B42318", borderRadius: 7, padding: "7px 10px", fontSize: 12, fontWeight: 800, cursor: "pointer" },
  formHint: { margin: "10px 0 0", color: "#667085", fontSize: 11, lineHeight: 1.5 },
  tableHeader: { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 12 },
  actionRow: { display: "flex", alignItems: "center", gap: 10, marginBottom: 10 },
  selectionSummary: { color: "#667085", fontSize: 11 },
  filterRow: { display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" },
  pageSummary: { fontSize: 11, color: "#667085", whiteSpace: "nowrap" },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 12 },
  th: { textAlign: "left", padding: "10px 12px", color: "#667085", borderBottom: "1px solid #e4e7ec" },
  thCheck: { width: 36, textAlign: "center", padding: "10px 8px", color: "#667085", borderBottom: "1px solid #e4e7ec" },
  td: { padding: "10px 12px", borderBottom: "1px solid #eef2f6", color: "#344054" },
  tdCheck: { width: 36, textAlign: "center", padding: "10px 8px", borderBottom: "1px solid #eef2f6" },
  tdMono: { padding: "10px 12px", borderBottom: "1px solid #eef2f6", color: "#173b70", fontFamily: "monospace", fontWeight: 700 },
  linkButton: { border: 0, background: "transparent", color: "#185FA5", fontSize: 12, fontWeight: 800, cursor: "pointer", padding: 0 },
  pagination: { display: "flex", justifyContent: "center", alignItems: "center", gap: 6, marginTop: 14, flexWrap: "wrap" },
};

function filterButton(active) {
  return {
    display: "inline-flex",
    alignItems: "center",
    gap: 8,
    border: `0.5px solid ${active ? "#185FA5" : "rgba(0,0,0,0.12)"}`,
    background: active ? "#185FA5" : "#FFFFFF",
    color: active ? "#FFFFFF" : "#6B7280",
    borderRadius: 999,
    padding: "6px 14px",
    fontSize: 12,
    fontWeight: active ? 700 : 500,
    cursor: "pointer",
    lineHeight: 1,
    boxShadow: active ? "0 1px 2px rgba(31,111,178,0.18)" : "none",
  };
}

function filterCount(active) {
  return {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    minWidth: 20,
    height: 16,
    padding: "0 6px",
    borderRadius: 999,
    background: active ? "rgba(255,255,255,0.24)" : "#EEF0F3",
    color: active ? "#FFFFFF" : "#8A94A6",
    fontSize: 10,
    fontWeight: 700,
  };
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

