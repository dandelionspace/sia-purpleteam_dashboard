import { sourceMatches } from "../utils/invariantSource";

const KPI_CONFIG = [
  ["invariant_total", "불변식 총계"],
  ["violated_invariant_count", "위반된 불변식"],
  ["applied_invariant_count", "적용된 불변식"],
  ["ai2_chain_scenario_count", "공격 체인 수"],
];

export default function KpiCards({ summary = {}, violations = [], invariants = [], activeFilter = "all", attackChains = [] }) {
  const filteredInvariants = activeFilter === "all"
    ? invariants
    : invariants.filter((inv) => sourceMatches(inv.invariant_source ?? inv.source, activeFilter));
  const filteredViolations = activeFilter === "all"
    ? violations
    : violations.filter((item) => sourceMatches(item.invariant_source ?? item.source, activeFilter));

  const invariantTotal = filteredInvariants.length || uniqueCount(violations.map((item) => item.invariant_id ?? item.id));
  const violatedCount  = filteredViolations.filter((v) => v.status === "violated").length;
  const appliedCount   = invariantTotal - violatedCount;

  const values = {
    ...summary,
    invariant_total:          invariantTotal,
    violated_invariant_count: violatedCount,
    applied_invariant_count:  appliedCount,
    ai2_chain_scenario_count: attackChains.length || summary.ai2_chain_scenario_count || 0,
  };

  return (
    <section style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginBottom: 32 }}>
      {KPI_CONFIG.map(([key, label]) => (
        <div key={key} style={styles.card}>
          <span style={styles.label}>{label}</span>
          <strong style={styles.value}>{values[key] ?? 0}</strong>
        </div>
      ))}
    </section>
  );
}

function uniqueCount(values) {
  return new Set(values.filter(Boolean)).size;
}

const styles = {
  card: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: "18px 20px", minHeight: 92 },
  label: { display: "block", fontSize: 12, color: "#73726c", marginBottom: 12 },
  value: { display: "block", fontSize: 28, color: "#173b70", letterSpacing: 0, fontWeight: 700 },
};
