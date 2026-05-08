import { useState, useEffect } from "react";
import { createInvariant } from "../services/scanService";
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip } from "recharts";

const SOURCE_TABS = [
  { id: "전체",     label: "전체" },
  { id: "fixed",    label: "고정 불변식" },
  { id: "variable", label: "가변 불변식" },
];

const STATUS_TABS = [
  { id: "전체",     label: "전체" },
  { id: "applied",  label: "통과" },
  { id: "violated", label: "위반" },
];

const SEVERITY_COLOR = {
  Critical: { bg: "#FEF1F1", text: "#C53030" },
  High:     { bg: "#FEF4EE", text: "#BF5520" },
  Medium:   { bg: "#FEF9E4", text: "#9C6F00" },
  Low:      { bg: "#F0FDF9", text: "#276749" },
};

const CATEGORY_OPTIONS     = ["접근제어", "보안정책", "네트워크", "권한"];
const ZONE_OPTIONS         = ["운영", "DB", "관리", "배포", "개발", "DMZ", "서명", "보안", "IoT"];
const SEVERITY_OPTIONS     = ["Critical", "High", "Medium", "Low"];
const ATTACK_PHASE_OPTIONS = ["초기침투", "자격증명", "권한상승", "방어우회", "데이터탈취"];

const EMPTY_FORM = {
  id: "", description: "", invariant_source: "fixed",
  severity: "", attack_phase: "",
  category: "", default_zone: "", weight: 1,
  remediation: "",
};

function Badge({ severity }) {
  const c = SEVERITY_COLOR[severity] || { bg: "#f1efea", text: "#444" };
  return (
    <span style={{ background: c.bg, color: c.text, fontSize: 10, fontWeight: 500, padding: "2px 8px", borderRadius: 99 }}>
      {severity || "—"}
    </span>
  );
}

function ViolationRateBar({ label, violated, total }) {
  const pct = total === 0 ? 0 : Math.round((violated / total) * 100);
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 5 }}>
        <span style={{ color: "#1a1a18", fontWeight: 500 }}>{label}</span>
        <span style={{ color: "#0C447C", fontWeight: 500 }}>{pct}% ({violated}/{total})</span>
      </div>
      <div style={{ height: 8, background: "#E6F1FB", borderRadius: 99, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: "#0C447C", borderRadius: 99, transition: "width 0.3s" }} />
      </div>
    </div>
  );
}

function Field({ label, required, children }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{ display: "block", fontSize: 11, fontWeight: 500, color: "#73726c", marginBottom: 5 }}>
        {label}{required && <span style={{ color: "#C53030", marginLeft: 2 }}>*</span>}
      </label>
      {children}
    </div>
  );
}

function AddInvariantDrawer({ open, onClose, onAdd, existingIds }) {
  const [form, setForm]     = useState(EMPTY_FORM);
  const [errors, setErrors] = useState({});

  const set = (key, val) => {
    setForm((f) => ({ ...f, [key]: val }));
    setErrors((e) => ({ ...e, [key]: undefined }));
  };

  const validate = () => {
    const e = {};
    if (!form.id.trim())          e.id          = "ID를 입력하세요";
    else if (existingIds.has(form.id.trim())) e.id = "이미 존재하는 ID입니다";
    if (!form.description.trim()) e.description = "불변식 내용을 입력하세요";
    return e;
  };

  const handleSubmit = () => {
    const e = validate();
    if (Object.keys(e).length > 0) { setErrors(e); return; }
    onAdd({ ...form, id: form.id.trim(), description: form.description.trim(), weight: Number(form.weight), status: "미점검", severity: null });
    setForm(EMPTY_FORM);
    setErrors({});
    onClose();
  };

  const handleClose = () => {
    setForm(EMPTY_FORM);
    setErrors({});
    onClose();
  };

  if (!open) return null;

  return (
    <>
      <div onClick={handleClose} style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.25)", zIndex: 100 }} />
      <div style={{
        position: "fixed", top: 0, right: 0, bottom: 0, width: 440,
        background: "#fff", zIndex: 101, overflowY: "auto",
        boxShadow: "-4px 0 24px rgba(0,0,0,0.10)", display: "flex", flexDirection: "column",
      }}>
        {/* 헤더 */}
        <div style={{ padding: "20px 24px 16px", borderBottom: "0.5px solid rgba(0,0,0,0.1)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <p style={{ fontSize: 15, fontWeight: 600, color: "#1a1a18", margin: 0 }}>불변식 추가</p>
            <p style={{ fontSize: 11, color: "#73726c", margin: "3px 0 0" }}>새 불변식 항목을 정의합니다</p>
          </div>
          <button onClick={handleClose} style={{ background: "none", border: "none", fontSize: 18, cursor: "pointer", color: "#73726c", padding: 4 }}>✕</button>
        </div>

        {/* 폼 */}
        <div style={{ padding: "20px 24px", flex: 1 }}>

          <Field label="불변식 ID" required>
            <input
              value={form.id}
              onChange={(e) => set("id", e.target.value)}
              placeholder="예) INV-ARG-09"
              style={{ ...inputStyle, borderColor: errors.id ? "#C53030" : "rgba(0,0,0,0.15)" }}
            />
            {errors.id && <p style={errorText}>{errors.id}</p>}
          </Field>

          <Field label="불변식 내용" required>
            <textarea
              value={form.description}
              onChange={(e) => set("description", e.target.value)}
              placeholder="불변식이 보장해야 하는 조건을 서술하세요"
              rows={3}
              style={{ ...inputStyle, resize: "vertical", borderColor: errors.description ? "#C53030" : "rgba(0,0,0,0.15)" }}
            />
            {errors.description && <p style={errorText}>{errors.description}</p>}
          </Field>

          <Field label="분류">
            <div style={{ display: "flex", gap: 8 }}>
              {[{ val: "fixed", label: "고정 불변식" }, { val: "variable", label: "가변 불변식" }].map(({ val, label }) => (
                <button
                  key={val}
                  onClick={() => set("invariant_source", val)}
                  style={{
                    flex: 1, padding: "8px 0", borderRadius: 8, border: "0.5px solid", cursor: "pointer", fontSize: 12,
                    borderColor: form.invariant_source === val ? "#185FA5" : "rgba(0,0,0,0.15)",
                    background:  form.invariant_source === val ? "#E6F1FB" : "#fff",
                    color:       form.invariant_source === val ? "#0C447C" : "#73726c",
                    fontWeight:  form.invariant_source === val ? 600 : 400,
                  }}
                >
                  {label}
                </button>
              ))}
            </div>
          </Field>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Field label="카테고리">
              <select value={form.category} onChange={(e) => set("category", e.target.value)} style={inputStyle}>
                <option value="">선택</option>
                {CATEGORY_OPTIONS.map((o) => <option key={o} value={o}>{o}</option>)}
              </select>
            </Field>
            <Field label="서버 존">
              <select value={form.default_zone} onChange={(e) => set("default_zone", e.target.value)} style={inputStyle}>
                <option value="">선택</option>
                {ZONE_OPTIONS.map((o) => <option key={o} value={o}>{o}</option>)}
              </select>
            </Field>
          </div>

          <Field label="공격 단계">
            <select value={form.attack_phase} onChange={(e) => set("attack_phase", e.target.value)} style={inputStyle}>
              <option value="">선택</option>
              {ATTACK_PHASE_OPTIONS.map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
          </Field>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Field label="가중치">
              <input
                type="number" min={1} max={10}
                value={form.weight}
                onChange={(e) => set("weight", e.target.value)}
                style={inputStyle}
              />
            </Field>
          </div>

          <Field label="조치 방법">
            <textarea
              value={form.remediation}
              onChange={(e) => set("remediation", e.target.value)}
              placeholder="위반 시 권고하는 조치 방법을 입력하세요"
              rows={3}
              style={{ ...inputStyle, resize: "vertical" }}
            />
          </Field>
        </div>

        {/* 하단 버튼 */}
        <div style={{ padding: "16px 24px", borderTop: "0.5px solid rgba(0,0,0,0.1)", display: "flex", gap: 8 }}>
          <button onClick={handleClose} style={{ flex: 1, padding: "10px 0", borderRadius: 8, border: "0.5px solid rgba(0,0,0,0.15)", background: "#fff", fontSize: 13, cursor: "pointer", color: "#73726c" }}>
            취소
          </button>
          <button onClick={handleSubmit} style={{ flex: 2, padding: "10px 0", borderRadius: 8, border: "none", background: "#0C447C", color: "#fff", fontSize: 13, fontWeight: 600, cursor: "pointer" }}>
            추가
          </button>
        </div>
      </div>
    </>
  );
}

export default function InvariantSection({ invariants: propInvariants }) {
  const [invariants, setInvariants] = useState(propInvariants ?? []);
  const [sourceTab, setSourceTab]   = useState("전체");
  const [statusTab, setStatusTab]   = useState("전체");
  const [drawerOpen, setDrawerOpen] = useState(false);

  // 스캔 전환 또는 외부 데이터 갱신 시 로컬 상태 동기화
  useEffect(() => {
    setInvariants(propInvariants ?? []);
  }, [propInvariants]);

  const existingIds = new Set(invariants.map((i) => i.id));

  const handleAdd = (newInv) => {
    // 로컬 state 즉시 반영 (낙관적 업데이트)
    setInvariants((prev) => [...prev, newInv]);
    // DB에 영속 저장 (실패해도 UI는 유지)
    createInvariant({
      id:               newInv.id,
      description:      newInv.description,
      invariant_source: newInv.invariant_source,
      severity:         newInv.severity     || "",
      attack_phase:     newInv.attack_phase || "",
      category:         newInv.category     || "",
      default_zone:     newInv.default_zone || "",
      weight:           newInv.weight       ?? 1,
      remediation:      newInv.remediation  || "",
    }).catch((e) => console.warn("불변식 저장 실패 (로컬에는 유지):", e));
  };

  const filtered = invariants.filter((inv) => {
    const sourceMatch = sourceTab === "전체" || inv.invariant_source === sourceTab;
    const statusMatch = statusTab === "전체" || inv.status === statusTab;
    return sourceMatch && statusMatch;
  });

  const total    = invariants.length;
  const fixed    = invariants.filter((i) => i.invariant_source === "fixed").length;
  const variable = invariants.filter((i) => i.invariant_source === "variable").length;
  const violated = invariants.filter((i) => i.status === "violated").length;
  const violationRate  = total === 0 ? 0 : Math.round((violated / total) * 100);
  const fixedViolated  = invariants.filter((i) => i.invariant_source === "fixed"    && i.status === "violated").length;
  const variableViolated = invariants.filter((i) => i.invariant_source === "variable" && i.status === "violated").length;

  const categoryStats = [...new Set(invariants.map((i) => i.category))].map((cat) => {
    const catItems   = invariants.filter((i) => i.category === cat);
    const catFiltered = sourceTab === "전체" ? catItems : catItems.filter((i) => i.invariant_source === sourceTab);
    return {
      category: cat,
      통과: catFiltered.filter((i) => i.status === "applied").length,
      위반: catFiltered.filter((i) => i.status === "violated").length,
    };
  }).filter((c) => c.통과 + c.위반 > 0);

  return (
    <div>
      <p style={sectionLabel}>불변식 목록</p>

      {/* KPI */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
        {[
          { label: "전체 불변식", value: total,           color: "#1a1a18" },
          { label: "고정 불변식", value: fixed,           color: "#0C447C" },
          { label: "가변 불변식", value: variable,        color: "#378ADD" },
          { label: "전체 위반율", value: `${violationRate}%`, color: "#0C447C" },
        ].map((k) => (
          <div key={k.label} style={{ background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: "14px 16px" }}>
            <p style={{ fontSize: 12, color: "#73726c", marginBottom: 6 }}>{k.label}</p>
            <p style={{ fontSize: 22, fontWeight: 500, color: k.color, margin: 0 }}>{k.value}</p>
          </div>
        ))}
      </div>

      {/* 통과율 + 카테고리 차트 */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
        <div style={card}>
          <p style={cardTitle}>고정/가변 위반율</p>
          <ViolationRateBar label="고정 불변식" violated={fixedViolated}   total={fixed} />
          <ViolationRateBar label="가변 불변식" violated={variableViolated} total={variable} />
          <ViolationRateBar label="전체"        violated={violated}         total={total} />
        </div>
        <div style={card}>
          <p style={cardTitle}>카테고리별 현황</p>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={categoryStats} layout="vertical" margin={{ left: 10, right: 20 }} barSize={10}>
              <XAxis type="number" tick={{ fontSize: 11, fill: "#73726c" }} />
              <YAxis dataKey="category" type="category" tick={{ fontSize: 11, fill: "#73726c" }} width={52} />
              <Tooltip />
              <Bar dataKey="통과" stackId="a" fill="#E6F1FB" radius={[0, 0, 0, 0]} />
              <Bar dataKey="위반" stackId="a" fill="#185FA5" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", gap: 12, marginTop: 6, fontSize: 11, color: "#73726c" }}>
            <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <span style={{ width: 10, height: 10, borderRadius: 2, background: "#E6F1FB", display: "inline-block" }} />통과
            </span>
            <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <span style={{ width: 10, height: 10, borderRadius: 2, background: "#185FA5", display: "inline-block" }} />위반
            </span>
          </div>
        </div>
      </div>

      {/* 필터 + 추가 버튼 */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
        <div style={{ display: "flex", gap: 6 }}>
          {SOURCE_TABS.map((tab) => (
            <button key={tab.id} onClick={() => setSourceTab(tab.id)} style={{
              padding: "5px 14px", borderRadius: 99, border: "0.5px solid", fontSize: 12, cursor: "pointer",
              borderColor: sourceTab === tab.id ? "#185FA5" : "rgba(0,0,0,0.12)",
              background:  sourceTab === tab.id ? "#185FA5" : "transparent",
              color:       sourceTab === tab.id ? "#fff" : "#73726c",
              fontWeight:  sourceTab === tab.id ? 500 : 400,
            }}>
              {tab.label}
              <span style={{
                marginLeft: 6, fontSize: 10, padding: "1px 6px", borderRadius: 99,
                background: sourceTab === tab.id ? "rgba(255,255,255,0.25)" : "rgba(0,0,0,0.06)",
                color:      sourceTab === tab.id ? "#fff" : "#73726c",
              }}>
                {invariants.filter((i) => tab.id === "전체" || i.invariant_source === tab.id).length}
              </span>
            </button>
          ))}
        </div>

        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {STATUS_TABS.map((tab) => {
            const isActive = statusTab === tab.id;
            const dotColor = tab.id === "applied" ? "#276749" : tab.id === "violated" ? "#C53030" : "#73726c";
            return (
              <button key={tab.id} onClick={() => setStatusTab(tab.id)} style={{
                padding: "5px 14px", borderRadius: 99, border: "0.5px solid", fontSize: 12, cursor: "pointer",
                borderColor: isActive ? dotColor : "rgba(0,0,0,0.12)",
                background:  isActive ? dotColor : "transparent",
                color:       isActive ? "#fff" : "#73726c",
                fontWeight:  isActive ? 500 : 400,
                display: "flex", alignItems: "center", gap: 4,
              }}>
                {tab.id === "applied"  && <span>✓</span>}
                {tab.id === "violated" && <span>●</span>}
                {tab.label}
              </button>
            );
          })}

          <button onClick={() => setDrawerOpen(true)} style={{
            padding: "5px 14px", borderRadius: 99, border: "none",
            background: "#0C447C", color: "#fff", fontSize: 12, fontWeight: 500, cursor: "pointer",
            display: "flex", alignItems: "center", gap: 5,
          }}>
            + 불변식 추가
          </button>
        </div>
      </div>

      {/* 불변식 테이블 */}
      <div style={card}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
          <p style={{ ...cardTitle, marginBottom: 0 }}>불변식 목록</p>
          <span style={{ fontSize: 11, color: "#73726c" }}>{filtered.length}건</span>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, tableLayout: "fixed" }}>
          <thead>
            <tr>
              {["ID", "불변식 내용", "분류", "카테고리", "서버 존", "가중치", "위험도", "상태"].map((h) => (
                <th key={h} style={h === "가중치" ? { ...th, textAlign: "center" } : th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((inv) => (
              <tr key={inv.id}>
                <td style={{ ...td, fontFamily: "monospace", fontSize: 11 }}>{inv.id}</td>
                <td style={{ ...td, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{inv.description}</td>
                <td style={td}>
                  <span style={{
                    fontSize: 10, padding: "2px 7px", borderRadius: 99, fontWeight: 500,
                    background: inv.invariant_source === "fixed" ? "#E6F1FB" : "#F0F6FE",
                    color:      inv.invariant_source === "fixed" ? "#0C447C" : "#378ADD",
                  }}>
                    {inv.invariant_source === "fixed" ? "고정" : "가변"}
                  </span>
                </td>
                <td style={{ ...td, color: "#73726c" }}>{inv.category || inv.type || "—"}</td>
                <td style={{ ...td, color: "#73726c" }}>{inv.default_zone || inv.server_zone || "—"}</td>
                <td style={{ ...td, color: "#73726c", textAlign: "center" }}>{inv.weight ?? "—"}</td>
                <td style={td}><Badge severity={inv.severity} /></td>
                <td style={td}>
                  {inv.status === "applied" ? (
                    <span style={{ color: "#0F6E56", fontWeight: 500, fontSize: 12 }}>✓ 통과</span>
                  ) : inv.status === "violated" ? (
                    <span style={{ color: "#C53030", fontWeight: 500, fontSize: 12 }}>위반</span>
                  ) : (
                    <span style={{ color: "#73726c", fontSize: 12 }}>미점검</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <AddInvariantDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onAdd={handleAdd}
        existingIds={existingIds}
      />
    </div>
  );
}

const inputStyle = {
  width: "100%", padding: "8px 10px", borderRadius: 8,
  border: "0.5px solid rgba(0,0,0,0.15)", fontSize: 12,
  color: "#1a1a18", outline: "none", boxSizing: "border-box",
  background: "#fff",
};
const errorText    = { fontSize: 10, color: "#C53030", margin: "4px 0 0" };
const sectionLabel = { fontSize: 11, fontWeight: 500, color: "#73726c", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 10 };
const card         = { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: 16, marginBottom: 12 };
const cardTitle    = { fontSize: 13, fontWeight: 500, marginBottom: 14 };
const th           = { textAlign: "left", color: "#73726c", fontWeight: 400, padding: "6px 8px", borderBottom: "0.5px solid rgba(0,0,0,0.1)" };
const td           = { padding: "7px 8px", borderBottom: "0.5px solid rgba(0,0,0,0.08)", color: "#1a1a18" };
