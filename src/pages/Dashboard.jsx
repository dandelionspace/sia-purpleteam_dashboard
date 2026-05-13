import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import AssetSection from "../components/AssetSection";
import AttackSection from "../components/AttackSection";
import DefenseSection from "../components/DefenseSection";
import EvidenceSection from "../components/EvidenceSection";
import InvariantSection from "../components/InvariantSection";
import ViolationAnalysisPage from "./ViolationAnalysisPage";
import KpiCards from "../components/KpiCards";
import PentestSection from "../components/PentestSection";
import ScanSection from "../components/ScanSection";
import ViolationSection from "../components/ViolationSection";
import { ACTIVE_API_BASE_URL, AI_PACK_API_BASE_URL, fetchHealth, fetchScanDetails, fetchScanList, USE_MOCK } from "../services/scanService";
import { sourceMatches } from "../utils/invariantSource";

const NAV_ITEMS = [
  { id: "evidence", icon: "EV", label: "Evidence", sections: ["evidence"] },
  { id: "overview", icon: "⚠️", label: "불변식 위반 현황", sections: ["kpi", "violation", "attack"] },
  { id: "assets", icon: "🧾", label: "자산 관리", sections: ["asset"] },
  { id: "invariants", icon: "📝", label: "불변식 상세", sections: ["invariant"] },
  { id: "pentest", icon: "🔓", label: "모의침투 결과", sections: ["pentest"] },
  { id: "defense", icon: "🛡️", label: "방어 및 보안 수준", sections: ["defense"] },
  { id: "scans", icon: "🔍", label: "점검 관리", sections: ["scan"] },
];

const FILTER_TABS = [
  { id: "all", label: "전체" },
  { id: "fixed", label: "고정 불변식" },
  { id: "custom", label: "가변 불변식" },
];

export default function Dashboard() {
  const [activeNav, setActiveNav] = useState("overview");
  const [activeFilter, setActiveFilter] = useState("all");
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [evidenceTarget, setEvidenceTarget] = useState(null); // { violation, invariant }

  const current = NAV_ITEMS.find((item) => item.id === activeNav) ?? NAV_ITEMS[0];

  const scanListQuery = useQuery({ queryKey: ["ai-pack-scans"], queryFn: fetchScanList });
  const healthQuery = useQuery({ queryKey: ["ai-pack-health"], queryFn: fetchHealth, retry: 1 });
  const scanList = useMemo(() => scanListQuery.data ?? [], [scanListQuery.data]);
  const latestScanId = useMemo(() => {
    if (!scanList.length) return null;
    const sorted = [...scanList].sort((a, b) => new Date(b.scanned_at ?? 0) - new Date(a.scanned_at ?? 0));
    return sorted[0]?.scan_id ?? null;
  }, [scanList]);
  const effectiveScanId = selectedScanId ?? latestScanId;
  const selectedScan = scanList.find((scan) => scan.scan_id === effectiveScanId);

  const detailsQuery = useQuery({
    queryKey: ["ai-pack-scan-details", effectiveScanId, selectedScan?.scanned_at],
    queryFn: () => fetchScanDetails(effectiveScanId, selectedScan),
    enabled: Boolean(effectiveScanId),
  });

  const detail = detailsQuery.data;

  const assetHistory = useMemo(() => {
    const points = detail?.securityPostureTimeline?.points ?? [];
    const timelinePoints = points.length > 1 ? points : buildTimelinePointsFromScans(scanList);
    const dayCounts = countByDay(timelinePoints.map((point) => point.created_at));
    return timelinePoints.map((point) => ({
      date: dayCounts[dateKey(point.created_at)] > 1 ? formatShortDateTime(point.created_at) : formatShortDate(point.created_at),
      tooltip_label: `${formatDate(point.created_at)} · ${point.run_id ?? "-"}`,
      scan_id: point.run_id,
      total: point.metrics?.asset_count ?? 0,
      with_violation: point.metrics?.violated_invariant_count ?? point.metrics?.total_violations ?? 0,
      changed_assets: metricOrArrayLength(point.metrics?.changed_asset_count, point.changed_assets),
      new_violations: metricOrArrayLength(point.metrics?.new_violation_count, point.new_violations_since_previous_run),
      resolved: metricOrArrayLength(point.metrics?.resolved_invariant_count, point.resolved_invariants_since_previous_run),
      changed_asset_ids: point.changed_assets ?? [],
      violated_invariants: point.violated_invariants ?? [],
      new_violations_since_previous_run: point.new_violations_since_previous_run ?? [],
      resolved_invariants_since_previous_run: point.resolved_invariants_since_previous_run ?? [],
    }));
  }, [detail, scanList]);
  const securityTimeline = useMemo(() => {
    const points = detail?.securityPostureTimeline?.points ?? [];
    return {
      ...(detail?.securityPostureTimeline ?? {}),
      points: points.length > 1 ? points : buildTimelinePointsFromScans(scanList),
    };
  }, [detail, scanList]);

  const violations = detail?.violations ?? [];
  const attackChains = detail?.attackChains ?? [];
  const pentestResults = detail?.pentestResults ?? [];
  const summary = detail?.summary ?? {};
  const error = scanListQuery.error || detailsQuery.error;

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: "#F8FAFC", color: "#1a1a18" }}>
      <aside style={styles.sidebar}>
        <div style={styles.brand}>
          <strong>ARGOS</strong>
          <span>Purple Team Dashboard</span>
        </div>

        <div style={styles.scanBox}>
          <span style={styles.mutedLabel}>PurpleTeam Backend API</span>
          <strong style={{ fontSize: 12 }}>{USE_MOCK ? "Mock mode" : ACTIVE_API_BASE_URL}</strong>
          <span style={{ ...styles.statusPill, background: healthQuery.isError ? "#fdecec" : "#e7f6ef", color: healthQuery.isError ? "#a32626" : "#116149" }}>
            {healthQuery.isError ? "disconnected" : healthQuery.data?.status ?? "checking"}
          </span>
          {AI_PACK_API_BASE_URL && <span style={{ fontSize: 10, color: "#98a2b3" }}>AI Pack URL is staging-only</span>}
        </div>

        <div style={styles.scanBox}>
          <span style={styles.mutedLabel}>Selected scan</span>
          <strong style={{ fontSize: 12, wordBreak: "break-all" }}>{selectedScan?.scan_id ?? "No scan"}</strong>
          <span style={{ fontSize: 11, color: "#8a94a6" }}>{formatDate(selectedScan?.scanned_at)}</span>
        </div>

        <nav style={{ padding: 12 }}>
          {NAV_ITEMS.map((item) => (
            <button
              key={item.id}
              onClick={() => {
                setActiveNav(item.id);
                setActiveFilter("all");
                setEvidenceTarget(null);
              }}
              style={navButton(activeNav === item.id)}
            >
              <span style={{ marginRight: 10 }}>{item.icon}</span>
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
      </aside>

      <main style={styles.main}>
        <header style={styles.header}>
          <div>
            <p style={styles.eyebrow}>PostgreSQL-backed PurpleTeam API / evidence-based security posture</p>
            <h1 style={styles.title}>{current.label}</h1>
          </div>
          <div style={{ textAlign: "right", fontSize: 12, color: "#667085" }}>
            <div>{detail?.scan_id ?? effectiveScanId ?? "-"}</div>
            <div>{formatDate(detail?.scanned_at ?? selectedScan?.scanned_at)}</div>
          </div>
        </header>

        {error && (
          <div style={styles.errorBox}>
            <strong>PurpleTeam backend connection failed.</strong>
            <span>{error.message}</span>
          </div>
        )}

        {detailsQuery.isLoading && !current.sections.includes("scan") ? (
          <div style={styles.empty}>Loading scan detail...</div>
        ) : (
          <>
            {current.sections.includes("scan") && (
              <ScanSection
                scanList={scanList}
                selectedScanId={effectiveScanId}
                onSelectScan={setSelectedScanId}
                onRefresh={scanListQuery.refetch}
                onTriggerComplete={scanListQuery.refetch}
              />
            )}

            {!current.sections.includes("scan") && (
              <>
                {activeNav === "overview" && !evidenceTarget && (
                  <div style={styles.filterRow}>
                    {FILTER_TABS.map((tab) => {
                      const invariants = detail?.invariants ?? [];
                      const count = tab.id === "all"
                        ? invariants.length
                        : invariants.filter((inv) => sourceMatches(inv.invariant_source ?? inv.source, tab.id)).length;
                      return (
                        <button key={tab.id} onClick={() => setActiveFilter(tab.id)} style={filterButton(activeFilter === tab.id)}>
                          {tab.label}
                          <span style={filterCount(activeFilter === tab.id)}>{count}</span>
                        </button>
                      );
                    })}
                  </div>
                )}

                {current.sections.includes("kpi") && !evidenceTarget && (
                  <KpiCards summary={summary} violations={violations} invariants={detail?.invariants ?? []} activeFilter={activeFilter} attackChains={attackChains} />
                )}

                {current.sections.includes("violation") && !evidenceTarget && (
                  <ViolationSection
                    violations={violations}
                    assets={detail?.assets ?? []}
                    invariants={detail?.invariants ?? []}
                    activeFilter={activeFilter}
                    onOpenEvidence={(violation, invariant) => setEvidenceTarget({ violation, invariant })}
                  />
                )}

                {current.sections.includes("violation") && evidenceTarget && (
                  <ViolationAnalysisPage
                    violation={evidenceTarget.violation}
                    invariant={evidenceTarget.invariant}
                    evidenceEvents={detail?.evidenceEvents ?? []}
                    violations={violations}
                    invariants={detail?.invariants ?? []}
                    onBack={() => setEvidenceTarget(null)}
                  />
                )}

                {current.sections.includes("attack") && !evidenceTarget && (
                  <AttackSection
                    attackChains={attackChains}
                    diagnosticRedteamCandidates={detail?.diagnosticRedteamCandidates ?? []}
                    mitreTacticMap={detail?.mitreTacticMap}
                    diagnosticMitreTacticMap={detail?.diagnosticMitreTacticMap}
                    violations={violations}
                    activeFilter={activeFilter}
                  />
                )}

                {current.sections.includes("evidence") && (
                  <EvidenceSection
                    evidenceEvents={detail?.evidenceEvents ?? []}
                    violations={violations}
                    invariants={detail?.invariants ?? []}
                  />
                )}

                {current.sections.includes("asset") && (
                  <AssetSection
                    assets={detail?.assets ?? []}
                    services={detail?.services ?? []}
                    summary={summary}
                    assetChanges={detail?.assetChanges ?? []}
                    assetReviewQueue={detail?.assetReviewQueue ?? []}
                    invariantImpact={detail?.invariantImpact ?? []}
                    violations={violations}
                    evidenceEvents={detail?.evidenceEvents ?? []}
                    assetHistory={assetHistory}
                    assetEvents={detail?.assetEvents ?? []}
                    assetHistoryMonthly={detail?.assetHistoryMonthly ?? []}
                    assetScanTrend={detail?.assetScanTrend ?? []}
                    securityPostureTimeline={securityTimeline}
                    activeScanId={effectiveScanId}
                  />
                )}

                {current.sections.includes("invariant") && (
                  <InvariantSection invariants={detail?.invariants ?? []} readiness={detail?.invariantReadiness ?? []} />
                )}

                {current.sections.includes("pentest") && (
                  <PentestSection pentestResults={pentestResults} scanId={effectiveScanId} attackChains={attackChains} />
                )}

                {current.sections.includes("defense") && (
                  <DefenseSection summary={summary} timeline={securityTimeline} violations={violations} activeScanId={effectiveScanId} scanCoverageMetrics={detail?.scanCoverageMetrics ?? []} />
                )}
              </>
            )}
          </>
        )}
      </main>
    </div>
  );
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("ko-KR", { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function formatShortDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString("ko-KR", { month: "short", day: "numeric" });
}

function formatShortDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("ko-KR", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function dateKey(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value ?? "";
  return date.toISOString().slice(0, 10);
}

function countByDay(values) {
  return values.reduce((counts, value) => {
    const key = dateKey(value);
    counts[key] = (counts[key] ?? 0) + 1;
    return counts;
  }, {});
}

function metricOrArrayLength(metric, items) {
  if (typeof metric === "number") return metric;
  if (Array.isArray(items)) return items.length;
  return 0;
}

function buildTimelinePointsFromScans(scans = []) {
  return [...scans]
    .filter((scan) => scan.scan_id && scan.scanned_at)
    .sort((a, b) => new Date(a.scanned_at) - new Date(b.scanned_at))
    .map((scan, index, sorted) => {
      const previous = sorted[index - 1];
      const assetCount = Number(scan.asset_count ?? 0);
      const previousAssetCount = Number(previous?.asset_count ?? assetCount);
      return {
        run_id: scan.scan_id,
        created_at: scan.scanned_at,
        metrics: {
          asset_count: assetCount,
          service_count: Number(scan.service_count ?? 0),
          total_violations: Number(scan.total_violations ?? 0),
          violated_invariant_count: Number(scan.total_violations ?? 0),
          asset_with_violation_count: Number(scan.with_violation_count ?? 0),
          changed_asset_count: index === 0 ? 0 : Math.abs(assetCount - previousAssetCount),
          new_violation_count: 0,
          resolved_invariant_count: 0,
          ai2_chain_scenario_count: Number(scan.attack_chains_count ?? 0),
        },
        changed_assets: [],
        violated_invariants: [],
        new_violations_since_previous_run: [],
        resolved_invariants_since_previous_run: [],
      };
    });
}

const styles = {
  sidebar: { width: 220, background: "#0F172A", color: "#fff", minHeight: "100vh", position: "sticky", top: 0, height: "100vh", flexShrink: 0 },
  brand: { padding: "24px 20px 20px", borderBottom: "0.5px solid rgba(255,255,255,0.08)", display: "flex", flexDirection: "column", gap: 4 },
  scanBox: { margin: 0, padding: "12px 20px", borderBottom: "0.5px solid rgba(255,255,255,0.08)", display: "flex", flexDirection: "column", gap: 6 },
  mutedLabel: { fontSize: 10, textTransform: "uppercase", letterSpacing: "0.07em", color: "#9CA3AF", fontWeight: 600 },
  statusPill: { width: "fit-content", borderRadius: 999, padding: "2px 8px", fontSize: 11, fontWeight: 700 },
  main: { flex: 1, minWidth: 0, padding: "32px 32px 64px", background: "#F8FAFC" },
  header: { display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 20, gap: 20 },
  eyebrow: { margin: "0 0 4px", fontSize: 11, color: "#73726c" },
  title: { margin: 0, fontSize: 20, fontWeight: 700, letterSpacing: 0, color: "#111827" },
  errorBox: { display: "flex", flexDirection: "column", gap: 3, background: "#FEF2F2", border: "0.5px solid #FECACA", color: "#991B1B", borderRadius: 10, padding: "12px 16px", marginBottom: 20, fontSize: 12 },
  filterRow: { display: "flex", alignItems: "center", gap: 8, marginBottom: 24 },
  empty: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: 40, textAlign: "center", color: "#73726c" },
};

function navButton(active) {
  return {
    width: "100%",
    border: "none",
    borderRadius: 8,
    padding: "10px 12px",
    marginBottom: 4,
    textAlign: "left",
    cursor: "pointer",
    background: active ? "#3B82F6" : "transparent",
    color: active ? "#FFFFFF" : "#9CA3AF",
    fontWeight: active ? 700 : 500,
    fontSize: 12,
    transition: "background 0.15s",
  };
}

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
