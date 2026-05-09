import { useMemo, useState } from "react";
import { createInvariant } from "../services/scanService";
import { EmptyRow, SectionTitle } from "./common";

const STATES = ["active", "disabled", "draft"];
const SOURCES = ["fixed", "custom"];
const APPROVAL = ["approved", "draft"];

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
  const [form, setForm] = useState({ invariant_id: "", title: "", source: "custom", state: "draft", approval_status: "draft" });
  const displayedInvariants = useMemo(() => mergeByInvariantId(invariants, localInvariants), [invariants, localInvariants]);

  const save = async () => {
    if (!form.invariant_id || !form.title) return;
    await createInvariant(form);
    setLocalInvariants((items) => upsert(items, form));
    setForm({ invariant_id: "", title: "", source: "custom", state: "draft", approval_status: "draft" });
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
        </div>
      </div>
      <div style={styles.card}>
        <table style={styles.table}>
          <thead>
            <tr>{["불변식 ID", "내용", "유형", "활성 여부", "승인 상태", "Readiness"].map((head) => <th key={head} style={styles.th}>{head}</th>)}</tr>
          </thead>
          <tbody>
            {displayedInvariants.map((item) => {
              const id = item.invariant_id ?? item.id;
              const ready = readiness.find((row) => row.invariant_id === id);
              return (
                <tr key={id}>
                  <td style={styles.tdMono}>{id}</td>
                  <td style={styles.td}>{displayTitle(item)}</td>
                  <td style={styles.td}>{labelFor(item.source ?? item.invariant_source)}</td>
                  <td style={styles.td}>{labelFor(item.state ?? (item.active === false ? "disabled" : "active"))}</td>
                  <td style={styles.td}>{labelFor(item.approval_status ?? item.catalog_status ?? "approved")}</td>
                  <td style={styles.td}>{ready?.status ?? ready?.reason ?? "-"}</td>
                </tr>
              );
            })}
            {!displayedInvariants.length && <EmptyRow colSpan={6} text="No invariant catalog returned." />}
          </tbody>
        </table>
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

function displayTitle(item) {
  const id = item.invariant_id ?? item.id;
  const candidates = [item.title, item.name, item.catalog_title, item.description];
  return candidates.find((v) => v && v !== id) ?? "DB 항목이 비어있습니다.";
}

function labelFor(value) {
  return VALUE_LABELS[value] ?? value ?? "-";
}

function upsert(items, item) {
  const id = item.invariant_id ?? item.id;
  const index = items.findIndex((candidate) => (candidate.invariant_id ?? candidate.id) === id);
  if (index < 0) return [...items, item];
  const next = [...items];
  next[index] = item;
  return next;
}

function mergeByInvariantId(remote, local) {
  const map = new Map(remote.map((item) => [item.invariant_id ?? item.id, item]));
  local.forEach((item) => map.set(item.invariant_id ?? item.id, item));
  return [...map.values()];
}

const styles = {
  card: { background: "#fff", border: "1px solid #e4e7ec", borderRadius: 8, padding: 16, marginBottom: 12 },
  cardTitle: { margin: "0 0 12px", fontSize: 14 },
  formGrid: { display: "grid", gridTemplateColumns: "1fr 2fr repeat(4, minmax(120px, auto))", gap: 8 },
  input: { border: "1px solid #d0d5dd", borderRadius: 7, padding: "8px 10px", fontSize: 13, fontFamily: "inherit", minWidth: 0 },
  primaryButton: { border: "none", background: "#2f6fed", color: "#fff", borderRadius: 7, padding: "8px 12px", fontWeight: 700, cursor: "pointer" },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 12 },
  th: { textAlign: "left", padding: "10px 12px", color: "#667085", borderBottom: "1px solid #e4e7ec" },
  td: { padding: "10px 12px", borderBottom: "1px solid #eef2f6", color: "#344054" },
  tdMono: { padding: "10px 12px", borderBottom: "1px solid #eef2f6", color: "#173b70", fontFamily: "monospace", fontWeight: 700 },
};
