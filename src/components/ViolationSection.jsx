import { useState } from "react";
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, ChipList, EmptyRow, SectionTitle } from "./common";

const SEVERITY_CHART_COLOR = {
  Critical: "#E05252",
  High: "#F0874A",
  Medium: "#F6C142",
  Low: "#38A169",
};

export default function ViolationSection({ violations = [], assets = [], invariants = [], activeFilter = "all" }) {
  const [selected, setSelected] = useState(null);
  const filtered = activeFilter === "all"
    ? violations
    : violations.filter((item) => (item.invariant_source ?? item.source) === activeFilter);
  const sourceRateStats = calcSourceRateStats(violations, invariants);
  const severityDist = calcSeverityDist(filtered);
  const zoneDist = calcZoneDist(filtered, assets);

  return (
    <section>
      <SectionTitle title="불변식 위반 현황" subtitle="AI 1 의 결과에 기반한 불변식 위반 현황" />
      <div style={styles.rateCard}>
        <h3 style={styles.chartTitle}>고정/가변 위반율</h3>
        {sourceRateStats.map((item) => (
          <ViolationRateBar key={item.label} {...item} />
        ))}
      </div>
      <div style={styles.chartGrid}>
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
              <Bar dataKey="count" fill="#4E87D4" radius={[0, 4, 4, 0]} barSize={14} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
      <div style={styles.card}>
        <table style={styles.table}>
          <thead>
            <tr>
              {["불변식 ID", "위반 여부", "위반 상세", "심각도", "신뢰도", "연관 증거", "자산", ""].map((head) => (
                <th key={head} style={styles.th}>{head}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((item) => (
              <tr key={item.result_id ?? item.invariant_id} style={styles.row}>
                <td style={styles.tdMono}>{item.invariant_id}</td>
                <td style={styles.td}>{item.status}</td>
                <td style={styles.td}>{item.violation_reason ?? "-"}</td>
                <td style={styles.td}><Badge value={item.severity} /></td>
                <td style={styles.td}>{formatConfidence(item.confidence)}</td>
                <td style={styles.td}><ChipList values={item.evidence_ids} /></td>
                <td style={styles.td}><ChipList values={item.asset_ids ?? item.affected_registry_asset_ids} /></td>
                <td style={{ ...styles.td, textAlign: "right" }}>
                  <button style={styles.linkButton} onClick={() => setSelected(item)}>상세 보기</button>
                </td>
              </tr>
            ))}
            {!filtered.length && <EmptyRow colSpan={8} text="불변식 위반 항목이 없습니다" />}
          </tbody>
        </table>
      </div>
      {selected && <ViolationDrawer violation={selected} onClose={() => setSelected(null)} />}
    </section>
  );
}

function ViolationDrawer({ violation, onClose }) {
  const trace = violation.ai1_trace ?? {};
  return (
    <div style={styles.overlay} onClick={onClose}>
      <aside style={styles.drawer} onClick={(event) => event.stopPropagation()}>
        <button onClick={onClose} style={styles.closeButton}>Close</button>
        <p style={styles.drawerEyebrow}>AI1 decision basis</p>
        <h2 style={styles.drawerTitle}>{violation.invariant_id}</h2>
        <p style={styles.bodyText}>{violation.summary ?? violation.reason ?? "No summary provided."}</p>
        <InfoBlock title="Reason" value={violation.reason} />
        <InfoBlock title="Evidence IDs" value={(violation.evidence_ids ?? []).join(", ")} />
        <InfoBlock title="Affected assets" value={(violation.affected_registry_asset_ids ?? violation.asset_ids ?? []).join(", ")} />
        <InfoBlock title="Affected services" value={(violation.affected_services ?? []).join(", ")} />
        <InfoBlock title="Affected zones" value={(violation.affected_zones ?? []).join(", ")} />
        <InfoBlock title="Required evidence types" value={(trace.required_evidence_types ?? []).join(", ")} />
        <InfoBlock title="Matched evidence IDs" value={(trace.matched_evidence_ids ?? []).join(", ")} />
        <InfoBlock title="Fields checked" value={(trace.fields_checked ?? []).join(", ")} />
        <InfoBlock title="Decision basis" value={trace.decision_basis} />
        <InfoBlock title="Missing fields" value={(trace.missing_fields ?? []).join(", ") || "None"} />
        <InfoBlock title="Current environment testable" value={String(violation.current_environment_testable ?? "-")} />
        <InfoBlock title="Testability reason" value={violation.testability_reason} />
      </aside>
    </div>
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

function InfoBlock({ title, value }) {
  if (!value) return null;
  return (
    <div style={styles.infoBlock}>
      <strong>{title}</strong>
      <p>{value}</p>
    </div>
  );
}

function formatConfidence(value) {
  if (typeof value !== "number") return "-";
  return `${Math.round(value * 100)}%`;
}

function calcSourceRateStats(violations, invariants) {
  const sourceOf = (item) => item.invariant_source ?? item.source ?? "";
  const isFixed = (item) => sourceOf(item) === "fixed";
  const isVariable = (item) => ["custom", "variable"].includes(sourceOf(item));

  const totalFixed = invariants.filter(isFixed).length;
  const totalVariable = invariants.filter(isVariable).length;
  const totalAll = invariants.length;

  const violatedFixed = violations.filter((v) => isFixed(v) && v.status === "violated").length;
  const violatedVariable = violations.filter((v) => isVariable(v) && v.status === "violated").length;
  const violatedAll = violations.filter((v) => v.status === "violated").length;

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
  const counts = {};
  const assetZoneById = buildAssetZoneMap(assets);
  list.forEach((item) => {
    const assetIds = asArray(item.asset_ids ?? item.affected_registry_asset_ids ?? item.affected_asset_ids);
    const zones = unique([
      ...asArray(item.affected_zones),
      ...assetIds.map((assetId) => assetZoneById[assetId]),
      item.zone,
      item.server_zone,
    ]).map(normalizeZone);
    const displayZones = zones.length ? unique(zones) : ["unknown"];
    displayZones.forEach((zone) => {
      const key = zone || "unknown";
      counts[key] = (counts[key] ?? 0) + 1;
    });
  });
  return Object.entries(counts)
    .map(([zone, count]) => ({ zone, count }))
    .sort((a, b) => b.count - a.count);
}

function buildAssetZoneMap(assets) {
  return Object.fromEntries(
    assets
      .map((asset) => [
        asset.asset_id ?? asset.id,
        asset.zone ?? asset.server_zone ?? asset.segment,
      ])
      .filter(([assetId, zone]) => assetId && zone)
  );
}

function asArray(value) {
  if (Array.isArray(value)) return value.filter(Boolean);
  return value ? [value] : [];
}

function unique(values) {
  return [...new Set(asArray(values))];
}

function normalizeZone(zone) {
  const key = String(zone ?? "").trim();
  const lower = key.toLowerCase();
  const labels = {
    ops: "운영",
    dmz: "DMZ",
    db: "DB",
    dev: "개발",
    deploy: "배포",
    security: "보안",
    management: "관리",
    backup: "백업",
  };
  return labels[lower] ?? key;
}

const styles = {
  rateCard: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: 16, marginBottom: 14 },
  rateItem: { marginBottom: 14 },
  rateHeader: { display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 12, marginBottom: 5, color: "#1a1a18", fontWeight: 500 },
  rateTrack: { height: 8, background: "#E6F1FB", borderRadius: 999, overflow: "hidden" },
  rateFill: { height: "100%", background: "#0C447C", borderRadius: 999, transition: "width 0.3s" },
  chartGrid: { display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 14, marginBottom: 26 },
  chartCard: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: 16, minHeight: 276 },
  chartTitle: { margin: "0 0 10px", fontSize: 13, fontWeight: 700, color: "#1a1a18" },
  legendRow: { display: "flex", flexWrap: "wrap", gap: 10, marginTop: 2, minHeight: 18 },
  legendItem: { display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11, color: "#667085" },
  legendSwatch: { width: 10, height: 10, borderRadius: 2, display: "inline-block" },
  emptyChartText: { fontSize: 12, color: "#98a2b3" },
  card: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, overflow: "hidden", marginBottom: 22, padding: "10px 18px 16px" },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 12 },
  th: { textAlign: "left", padding: "9px 10px", color: "#73726c", borderBottom: "0.5px solid rgba(0,0,0,0.1)", fontWeight: 500 },
  td: { padding: "9px 10px", borderBottom: "0.5px solid rgba(0,0,0,0.08)", color: "#1a1a18", verticalAlign: "top" },
  tdMono: { padding: "9px 10px", borderBottom: "0.5px solid rgba(0,0,0,0.08)", color: "#111827", fontFamily: "monospace", fontWeight: 500 },
  row: { background: "#fff" },
  linkButton: { border: "none", background: "transparent", color: "#185FA5", fontSize: 11, fontWeight: 700, cursor: "pointer", padding: 0 },
  overlay: { position: "fixed", inset: 0, zIndex: 50, background: "rgba(0,0,0,0.15)", display: "flex", justifyContent: "flex-end" },
  drawer: { width: 480, maxWidth: "100vw", background: "#fff", height: "100%", overflowY: "auto", padding: "20px 24px", boxShadow: "-4px 0 24px rgba(0,0,0,0.08)" },
  closeButton: { float: "right", border: "none", background: "transparent", color: "#73726c", fontSize: 13, fontWeight: 700, padding: 0, cursor: "pointer" },
  drawerEyebrow: { margin: "0 0 4px", fontSize: 10, color: "#73726c", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 },
  drawerTitle: { margin: "0 0 12px", fontSize: 18, color: "#0C447C", fontFamily: "monospace", fontWeight: 700 },
  bodyText: { background: "#f5f5f3", borderRadius: 10, padding: 14, fontSize: 12, lineHeight: 1.6, color: "#1a1a18", margin: "0 0 16px" },
  infoBlock: { borderTop: "0.5px solid rgba(0,0,0,0.08)", padding: "12px 0", fontSize: 12, lineHeight: 1.55, color: "#1a1a18" },
};
