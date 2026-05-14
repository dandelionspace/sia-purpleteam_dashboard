import { buildInvariantJudgmentCounts } from "../utils/invariantJudgment";
import { sourceMatches } from "../utils/invariantSource";

const KPI_CONFIG = [
  ["invariant_total", "전체 불변식", "default"],
  ["confirmed_violation_count", "확정 위반", "alert"],
  ["unverifiable_invariant_count", "검증 불가", "default"],
  ["normal_or_not_observed_count", "정상/위반 미관측", "default"],
  ["critical_high", "Critical/High 위반", "default"],
];

export default function KpiCards({
  summary = {},
  violations = [],
  invariants = [],
  activeFilter = "all",
}) {
  const filteredInvariants = activeFilter === "all"
    ? invariants
    : invariants.filter((inv) => sourceMatches(inv.invariant_source ?? inv.source, activeFilter));
  const filteredViolations = activeFilter === "all"
    ? violations
    : violations.filter((item) => sourceMatches(item.invariant_source ?? item.source, activeFilter));

  const invariantTotal = filteredInvariants.length || uniqueCount(violations.map((item) => item.invariant_id ?? item.id));
  const judgmentCounts = buildInvariantJudgmentCounts(filteredInvariants, filteredViolations);
  const criticalHigh = filteredViolations.filter((v) => ["Critical", "High"].includes(v.severity)).length;

  const values = {
    ...summary,
    invariant_total: invariantTotal,
    confirmed_violation_count: judgmentCounts.confirmedViolation,
    unverifiable_invariant_count: judgmentCounts.unverifiable,
    normal_or_not_observed_count: judgmentCounts.normalOrNotObserved,
    critical_high: criticalHigh || summary.critical_high || 0,
  };

  return (
    <section style={styles.grid}>
      {KPI_CONFIG.map(([key, label, tone]) => (
        <div key={key} style={{ ...styles.card, ...toneStyle(tone).card }}>
          <span style={styles.label}>{label}</span>
          <strong style={{ ...styles.value, ...toneStyle(tone).value }}>{values[key] ?? 0}</strong>
        </div>
      ))}
    </section>
  );
}

function uniqueCount(values) {
  return new Set(values.filter(Boolean)).size;
}

function toneStyle(tone) {
  if (tone === "alert") {
    return { card: { background: "#FFF7F7", borderColor: "#FECACA" }, value: { color: "#991B1B" } };
  }
  return { card: {}, value: {} };
}

const styles = {
  grid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
    gap: 12,
    marginBottom: 32,
  },
  card: {
    background: "#fff",
    border: "0.5px solid rgba(0,0,0,0.1)",
    borderRadius: 8,
    padding: "18px 20px",
    minHeight: 92,
  },
  label: { display: "block", fontSize: 12, color: "#73726c", marginBottom: 12 },
  value: { display: "block", fontSize: 28, color: "#173b70", letterSpacing: 0, fontWeight: 700 },
};
