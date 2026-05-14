import { Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useState } from "react";
import { ChipList, EmptyRow, SectionTitle } from "./common";
import { formatServerZone } from "../utils/zoneDisplay";

const PAGE_SIZE = 10;

function ExpandableChipList({ values = [], max = 3 }) {
  const [expanded, setExpanded] = useState(false);
  if (!values.length) return <span style={{ color: "#98a2b3" }}>-</span>;
  const visible = expanded ? values : values.slice(0, max);
  const hidden = values.length - max;
  return (
    <span style={{ display: "flex", flexWrap: "wrap", gap: 4, alignItems: "center" }}>
      {visible.map((value) => (
        <span key={value} style={{ borderRadius: 4, padding: "2px 7px", background: "#F1F5F9", color: "#475569", fontSize: 10 }}>{value}</span>
      ))}
      {!expanded && hidden > 0 && (
        <button type="button" onClick={() => setExpanded(true)} style={{ borderRadius: 4, padding: "2px 7px", background: "#EEF4FD", color: "#185FA5", fontSize: 10, border: "none", cursor: "pointer" }}>
          +{hidden} 더 보기
        </button>
      )}
      {expanded && values.length > max && (
        <button type="button" onClick={() => setExpanded(false)} style={{ borderRadius: 4, padding: "2px 7px", background: "#EEF4FD", color: "#185FA5", fontSize: 10, border: "none", cursor: "pointer" }}>
          접기
        </button>
      )}
    </span>
  );
}
const MAX_PAGE_BUTTONS = 10;

const EVENT_TYPE_STYLE = {
  asset_updated:   { label: "자산 변경",   bg: "#FEF3C7", color: "#92400E" },
  asset_created:   { label: "신규 등록",   bg: "#D1FAE5", color: "#065F46" },
  asset_removed:   { label: "자산 삭제",   bg: "#FEE2E2", color: "#991B1B" },
  service_added:   { label: "서비스 추가", bg: "#EDE9FE", color: "#5B21B6" },
  service_removed: { label: "서비스 제거", bg: "#FEE2E2", color: "#991B1B" },
};

const CHANGE_EVENT_TYPES = new Set(["asset_created", "asset_updated", "asset_removed"]);

export default function AssetSection({ assets = [], services = [], summary = {}, assetChanges = [], assetReviewQueue = [], invariantImpact = [], violations = [], evidenceEvents = [], assetHistory = [], assetEvents = [], assetHistoryMonthly = [], assetScanTrend = [], securityPostureTimeline = { points: [] }, activeScanId = null }) {
  const countedAssets = getCountedAssets(assets);
  const violatedAssetIds = buildViolatedAssetIds(invariantImpact, violations);
  const currentViolatedAssetCount = countAssetsByIds(countedAssets, violatedAssetIds);
  const totalAssetCount = summary.asset_count ?? countedAssets.length;
  const changedAssetCount = summary.changed_asset_count ?? getCurrentTimelineMetric(securityPostureTimeline, activeScanId, "changed_asset_count") ?? countChangedAssetIds(assetEvents);
  const unregisteredAssetCount = assets.filter((asset) => asset.observation_status === "unregistered_asset_candidate").length;
  return (
    <section>
      <SectionTitle title="자산 관리" subtitle="자산 현황, 위반 연관 자산 및 변경 이력 추적" />
      <Summary totalAssetCount={totalAssetCount} changedAssetCount={changedAssetCount} unregisteredAssetCount={unregisteredAssetCount} currentViolatedAssetCount={currentViolatedAssetCount} />
      <div style={styles.chartGrid}>
        <AssetViolationChart assetScanTrend={assetScanTrend} securityPostureTimeline={securityPostureTimeline} assetHistoryMonthly={assetHistoryMonthly} assets={countedAssets} currentViolatedAssetCount={currentViolatedAssetCount} activeScanId={activeScanId} />
        <AssetChangeChart assetEvents={assetEvents} securityPostureTimeline={securityPostureTimeline} assetHistoryMonthly={assetHistoryMonthly} assetChanges={assetChanges} assetScanTrend={assetScanTrend} />
      </div>
      <ServerAssetDistribution assets={countedAssets} violations={violations} violatedAssetIds={violatedAssetIds} />
      <AssetDetailTable assets={countedAssets} services={services} invariantImpact={invariantImpact} violations={violations} />
      <RecentChangedAssetTable assetEvents={assetEvents} assets={assets} />
    </section>
  );
}

function Summary({ totalAssetCount, changedAssetCount, unregisteredAssetCount, currentViolatedAssetCount }) {
  const cards = [
    ["총 자산", totalAssetCount],
    ["위반 연관 자산", currentViolatedAssetCount],
    ["변경된 자산", changedAssetCount],
    ["미등록 자산", unregisteredAssetCount],
  ];
  return (
    <div style={styles.summaryGrid}>
      {cards.map(([label, value]) => (
        <div key={label} style={styles.card}>
          <span style={styles.label}>{label}</span>
          <strong style={styles.value}>{value}</strong>
        </div>
      ))}
    </div>
  );
}

function buildViolatedAssetIds(invariantImpact, violations) {
  return new Set(uniqueList(
    invariantImpact.flatMap((item) => uniqueList(
      item.affected_registry_asset_ids,
      item.asset_ids,
      item.affected_asset_ids,
      item.asset_id,
      toList(item.affected_assets).map(getAssetId)
    )),
    violations.flatMap((violation) => uniqueList(
      violation.asset_ids,
      violation.affected_asset_ids,
      violation.affected_registry_asset_ids,
      violation.affected_resource_ids,
      violation.invariant_impact?.affected_registry_asset_ids,
      violation.invariant_impact?.asset_ids,
      toList(violation.affected_assets).map(getAssetId),
      toList(violation.assets).map(getAssetId)
    ))
  ));
}

function AssetViolationChart({ assetScanTrend, securityPostureTimeline, assetHistoryMonthly, assets, currentViolatedAssetCount, activeScanId }) {
  // 1순위: 스캔별 실측 추이 (scans + scan_asset_snapshot)
  // 같은 날 여러 스캔이 있어도 tooltip이 올바른 포인트를 가리키도록 인덱스를 XAxis key로 사용
  const trendData = buildAssetViolationTrend(assetScanTrend, securityPostureTimeline, currentViolatedAssetCount, activeScanId);
  if (trendData.length > 0) {
    return (
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>전체 자산 & 위반 위협 자산 수 추이</h3>
        {trendData.some((row) => row.with_violation == null) && (
          <p style={styles.note}>이전 스캔의 위반 위협 자산 수는 산출물에 저장된 경우에만 표시됩니다.</p>
        )}
        <ResponsiveContainer width="100%" height={240}>
          <LineChart data={trendData} margin={{ top: 4, right: 8, left: 0, bottom: 4 }}>
            <CartesianGrid stroke="#eef2f6" />
            <XAxis dataKey="_idx" tickFormatter={(i) => trendData[i]?.month ?? ""} tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
            <Tooltip labelFormatter={(i) => trendData[i]?.month ?? ""} formatter={(value, name) => [value ?? "데이터 없음", name]} />
            <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11 }} />
            <Line dataKey="total" name="전체 자산" stroke="#2f6fed" strokeWidth={2} dot={{ r: 3 }} />
            <Line dataKey="with_violation" name="위반 위협 자산" stroke="#d92d20" strokeWidth={2} dot={{ r: 3 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    );
  }

  // 2순위: 월별 집계 이력 (asset_history_monthly)
  if (assetHistoryMonthly.length > 0) {
    const chartData = assetHistoryMonthly.map((row, i) => ({
      _idx: i,
      month: row.date_label ?? String(row.period_start ?? "").slice(0, 7),
      total: row.total ?? 0,
      with_violation: row.vulnerable ?? 0,
    }));
    return (
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>전체 자산 & 위반 위협 자산 수 추이</h3>
        <ResponsiveContainer width="100%" height={240}>
          <LineChart data={chartData} margin={{ top: 4, right: 8, left: 0, bottom: 4 }}>
            <CartesianGrid stroke="#eef2f6" />
            <XAxis dataKey="_idx" tickFormatter={(i) => chartData[i]?.month ?? ""} tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
            <Tooltip labelFormatter={(i) => chartData[i]?.month ?? ""} />
            <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11 }} />
            <Line dataKey="total" name="전체 자산" stroke="#2f6fed" strokeWidth={2} dot={{ r: 3 }} />
            <Line dataKey="with_violation" name="위반 위협 자산" stroke="#d92d20" strokeWidth={2} dot={{ r: 3 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    );
  }

  // 월별 이력 없으면 현재 스냅샷을 단일 포인트로 표시
  // invariantImpact가 비어 있을 경우 violations.asset_ids로 fallback
  const chartData = [{ month: "현재", total: assets.length, vulnerable: currentViolatedAssetCount }];
  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle}>전체 자산 & 위반 위협 자산 수 (현재)</h3>
      <p style={{ fontSize: 11, color: "#98a2b3", margin: "0 0 12px" }}>월별 이력 데이터 없음 — 현재 스캔 기준</p>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={chartData} margin={{ top: 4, right: 8, left: 0, bottom: 4 }}>
          <CartesianGrid stroke="#eef2f6" />
          <XAxis dataKey="month" tick={{ fontSize: 11 }} />
          <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
          <Tooltip />
          <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11 }} />
          <Bar dataKey="total" name="전체 자산" fill="#2f6fed" />
          <Bar dataKey="vulnerable" name="위반 위협 자산" fill="#d92d20" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function AssetChangeChart({ assetEvents, securityPostureTimeline, assetHistoryMonthly, assetChanges, assetScanTrend }) {
  const timelineChangeData = buildAssetChangeTrend(securityPostureTimeline);
  if (timelineChangeData.length > 0) {
    const isTrend = timelineChangeData.length > 1;
    return (
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>{isTrend ? "신규 등록 & 변경 & 제거 자산 수 추이" : "신규 등록 & 변경 & 제거 자산 수 (현재 스캔)"}</h3>
        <p style={styles.note}>
          {isTrend
            ? "스캔별 new_asset_count, updated_asset_count, changed_asset_count 기준입니다."
            : "현재 응답에 과거 스캔 메트릭이 없어 현재 스캔 값만 표시합니다."}
        </p>
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={timelineChangeData} margin={{ top: 4, right: 8, left: 0, bottom: 4 }}>
            <CartesianGrid stroke="#eef2f6" />
            <XAxis dataKey="_idx" tickFormatter={(index) => timelineChangeData[index]?.label ?? ""} tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
            <Tooltip labelFormatter={(index) => timelineChangeData[index]?.tooltip_label ?? ""} />
            <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11 }} />
            <Bar dataKey="asset_created" name="신규 등록" fill="#12b76a" />
            <Bar dataKey="asset_updated" name="변경" fill="#2f6fed" />
            <Bar dataKey="asset_removed" name="제거" fill="#d92d20" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    );
  }

  // 1순위: assetEvents(DB)를 월별로 그룹핑 — occurred_at 없으면 "날짜 미상" 버킷
  const monthMap = {};
  assetEvents.forEach((ev) => {
    if (!CHANGE_EVENT_TYPES.has(ev.event_type)) return;
    if (!ev.occurred_at) return;
    const month = ev.occurred_at ? String(ev.occurred_at).slice(0, 7) : "날짜 미상";
    if (!monthMap[month]) monthMap[month] = { month, asset_created: 0, asset_updated: 0, asset_removed: 0 };
    monthMap[month][ev.event_type]++;
  });
  const eventChartData = Object.values(monthMap).sort((a, b) => a.month.localeCompare(b.month));

  if (eventChartData.length > 0) {
    return (
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>신규 등록 & 변경 & 제거 자산 수 추이</h3>
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={eventChartData} margin={{ top: 4, right: 8, left: 0, bottom: 4 }}>
            <CartesianGrid stroke="#eef2f6" />
            <XAxis dataKey="month" tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
            <Tooltip />
            <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11 }} />
            <Bar dataKey="asset_created" name="신규 등록" fill="#12b76a" />
            <Bar dataKey="asset_updated" name="변경" fill="#2f6fed" />
            <Bar dataKey="asset_removed" name="제거" fill="#d92d20" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    );
  }

  // 2순위: assetHistoryMonthly — 신규 등록 월별 추이
  if (assetHistoryMonthly.length > 0) {
    const chartData = assetHistoryMonthly.map((row) => ({
      month: row.date_label ?? String(row.period_start ?? "").slice(0, 7),
      asset_created: row.new_assets ?? 0,
      asset_updated: 0,
      asset_removed: 0,
    }));
    return (
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>신규 등록 & 변경 & 제거 자산 수 추이</h3>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={chartData} margin={{ top: 4, right: 8, left: 0, bottom: 4 }}>
            <CartesianGrid stroke="#eef2f6" />
            <XAxis dataKey="month" tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
            <Tooltip />
            <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11 }} />
            <Bar dataKey="asset_created" name="신규 등록" fill="#12b76a" />
            <Bar dataKey="asset_updated" name="변경" fill="#2f6fed" />
            <Bar dataKey="asset_removed" name="제거" fill="#d92d20" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    );
  }

  // 3순위: assetScanTrend로 스캔 간 자산 수 증감 계산 — assetEvents/assetHistoryMonthly 모두 없을 때
  // 연속 스캔의 total 차이로 신규 등록·제거 수를 근사
  if (assetScanTrend.length > 1) {
    const sorted = [...assetScanTrend]
      .filter((r) => r.date_label || r.scanned_at)
      .sort((a, b) => (a.scanned_at ?? "").localeCompare(b.scanned_at ?? ""));
    const scanChangeData = sorted
      .map((row, i) => {
        const prev = sorted[i - 1];
        const cur = row.total ?? 0;
        const pre = prev?.total ?? cur;
        const delta = cur - pre;
        return {
          month: row.date_label ?? String(row.scanned_at ?? "").slice(0, 10),
          asset_created: i === 0 ? cur : Math.max(0, delta),
          asset_updated: 0,
          asset_removed: i === 0 ? 0 : Math.max(0, -delta),
        };
      })
      .filter((r) => r.month);
    if (scanChangeData.length > 1) {
      return (
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>신규 등록 & 제거 자산 수 추이 (스캔 기준)</h3>
          <p style={{ fontSize: 11, color: "#98a2b3", margin: "0 0 12px" }}>이벤트 이력 없음 — 스캔별 자산 수 증감 기준</p>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={scanChangeData} margin={{ top: 4, right: 8, left: 0, bottom: 4 }}>
              <CartesianGrid stroke="#eef2f6" />
              <XAxis dataKey="month" tick={{ fontSize: 11 }} />
              <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
              <Tooltip />
              <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11 }} />
              <Bar dataKey="asset_created" name="신규 등록" fill="#12b76a" />
              <Bar dataKey="asset_removed" name="제거" fill="#d92d20" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      );
    }
  }

  // 최종 fallback: 데이터 없음 안내
  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle}>신규 등록 & 변경 & 제거 자산 수 추이</h3>
      <p style={{ fontSize: 11, color: "#98a2b3", margin: "0 0 12px" }}>자산 변경 이력 데이터 없음</p>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={[{ month: "데이터 없음", asset_created: 0, asset_updated: 0, asset_removed: 0 }]} margin={{ top: 4, right: 8, left: 0, bottom: 4 }}>
          <CartesianGrid stroke="#eef2f6" />
          <XAxis dataKey="month" tick={{ fontSize: 11 }} />
          <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
          <Tooltip />
          <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: 11 }} />
          <Bar dataKey="asset_created" name="신규 등록" fill="#12b76a" />
          <Bar dataKey="asset_updated" name="변경" fill="#2f6fed" />
          <Bar dataKey="asset_removed" name="제거" fill="#d92d20" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function ServerAssetDistribution({ assets, violations, violatedAssetIds }) {
  const rows = buildServerDistributionRows(assets, violations, violatedAssetIds);
  const maxAssets = Math.max(...rows.map((row) => row.asset_count), 1);
  if (!assets.length) return null;

  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle}>서버별 자산 분포</h3>
      <table style={styles.table}>
        <thead>
          <tr>
            <HelpHeader label="vm" help="자산이 배치되거나 관측된 서버 VM 이름입니다." />
            <HelpHeader label="자산 수" help="해당 VM에 속한 등록 자산 수입니다. 미등록 후보 자산은 제외합니다." />
            <HelpHeader label="Critical/High 영향 자산" help="Critical 또는 High 위반에 1회 이상 연결된 unique 자산 수입니다. 같은 자산에 위반이 여러 개 있어도 1개로 셉니다." />
            <HelpHeader label="Critical/High 위반 링크" help="Critical 또는 High 위반 항목과 자산의 연결 수입니다. 같은 자산에 여러 위반이 있으면 여러 건으로 셉니다." />
            <HelpHeader label="위반 위협 자산" help="전체 위반 항목에 연결된 unique 자산 수입니다. severity와 무관하게 위반 영향 자산을 셉니다." />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.vm}>
              <td style={styles.tdMono}>{row.vm}</td>
              <td style={styles.td}>
                <MetricBar value={row.asset_count} max={maxAssets} color="#2f6fed" />
              </td>
              <td style={styles.td}>{row.critical_high_assets}</td>
              <td style={styles.td}>{row.critical_high_links}</td>
              <td style={styles.td}>{row.violated_related_assets}</td>
            </tr>
          ))}
          {!rows.length && <EmptyRow colSpan={5} text="서버별 자산 분포 데이터가 없습니다" />}
        </tbody>
      </table>
    </div>
  );
}

function HelpHeader({ label, help }) {
  return (
    <th style={styles.th}>
      <span style={styles.helpHeader}>
        {label}
        <span style={styles.helpBadge} title={help}>?</span>
      </span>
    </th>
  );
}

function MetricBar({ value, max, color }) {
  const width = max ? Math.max(4, Math.round((value / max) * 100)) : 0;
  return (
    <div style={styles.metricBarCell}>
      <span style={styles.metricBarValue}>{value}</span>
      <span style={styles.metricBarTrack}>
        <span style={{ ...styles.metricBarFill, width: `${width}%`, background: color }} />
      </span>
    </div>
  );
}

function buildServerDistributionRows(assets, violations, violatedAssetIds) {
  const assetById = buildAssetIdMap(assets);
  const groups = {};
  assets.forEach((asset) => {
    const vm = asset.vm ?? asset.hostname ?? asset.server ?? asset.producer_vm ?? "unknown";
    if (!groups[vm]) {
      groups[vm] = { vm, assets: [], criticalHighAssetIds: new Set(), criticalHighViolationLinks: new Set() };
    }
    groups[vm].assets.push(asset);
  });

  violations.forEach((violation) => {
    if (!["Critical", "High"].includes(violation.severity)) return;
    const violationKey = violation.result_id ?? violation.violation_id ?? violation.id ?? violation.invariant_id;
    getViolationAssetIds(violation)
      .map((assetId) => assetById[assetId])
      .filter(Boolean)
      .forEach((asset) => {
        const assetId = asset.asset_id ?? asset.id;
        const vm = asset.vm ?? asset.hostname ?? asset.server ?? asset.producer_vm ?? "unknown";
        groups[vm]?.criticalHighAssetIds.add(assetId);
        groups[vm]?.criticalHighViolationLinks.add(`${violationKey}::${assetId}`);
      });
  });

  return Object.values(groups)
    .map((group) => ({
      vm: group.vm,
      asset_count: group.assets.length,
      critical_high_assets: group.criticalHighAssetIds.size,
      critical_high_links: group.criticalHighViolationLinks.size,
      violated_related_assets: group.assets.filter((asset) => getAssetReferenceKeys(asset).some((assetId) => violatedAssetIds.has(assetId))).length,
    }))
    .sort((a, b) => b.violated_related_assets - a.violated_related_assets || b.critical_high_links - a.critical_high_links || b.critical_high_assets - a.critical_high_assets || b.asset_count - a.asset_count || a.vm.localeCompare(b.vm));
}

function AssetDetailTable({ assets, services, invariantImpact, violations }) {
  const [page, setPage] = useState(1);
  const impactByAsset = buildImpactByAsset(invariantImpact, violations);
  const servicesByAsset = buildServicesByAsset(services, assets);
  const { pageItems, currentPage, totalPages } = paginate(assets, page);
  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle}>자산 상세 목록</h3>
      <TableMeta total={assets.length} currentPage={currentPage} totalPages={totalPages} />
      <table style={styles.table}>
        <thead>
          <tr>
            {["자산 이름", "자산 id", "category", "type", "내부/외부 노출 수준", "서비스", "관련 불변식"].map((head) => (
              <th key={head} style={styles.th}>{head}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {pageItems.map((asset) => (
            <tr key={asset.asset_id}>
              <td style={styles.td}>{asset.name ?? asset.asset_name ?? "-"}</td>
              <td style={styles.tdMono}>{asset.asset_id}</td>
              <td style={styles.td}>{asset.category ?? asset.asset_category ?? "-"}</td>
              <td style={styles.td}>{asset.asset_type ?? asset.type ?? "-"}</td>
              <td style={styles.td}>{asset.exposure ?? asset.exposure_level ?? asset.internet_exposure ?? "-"}</td>
              <td style={styles.td}>
                <ExpandableChipList values={getMappedValuesByAsset(servicesByAsset, asset)} />
              </td>
              <td style={styles.td}>
                <ExpandableChipList values={getMappedValuesByAsset(impactByAsset, asset)} />
              </td>
            </tr>
          ))}
          {!assets.length && <EmptyRow colSpan={7} text="자산이 없습니다" />}
        </tbody>
      </table>
      <Pagination page={currentPage} totalPages={totalPages} onPageChange={setPage} />
    </div>
  );
}

function RecentChangedAssetTable({ assetEvents, assets }) {
  const [page, setPage] = useState(1);
  const assetById = Object.fromEntries(assets.map((a) => [a.asset_id, a]));
  const changeEvents = assetEvents
    .filter((ev) => CHANGE_EVENT_TYPES.has(ev.event_type) && ev.asset_id)
    .sort((a, b) => eventTimeValue(b) - eventTimeValue(a));
  const { pageItems, currentPage, totalPages } = paginate(changeEvents, page);

  if (!changeEvents.length) return null;

  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle}>최신 변경된 자산 목록</h3>
      <TableMeta total={changeEvents.length} currentPage={currentPage} totalPages={totalPages} />
      <table style={styles.table}>
        <thead>
          <tr>
            {["변경 유형", "자산 ID", "자산 유형", "자산 위치", "변경 시간"].map((h) => (
              <th key={h} style={styles.th}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {pageItems.map((ev) => {
            const typeStyle = EVENT_TYPE_STYLE[ev.event_type] ?? { label: ev.event_type ?? "-", bg: "#F3F4F6", color: "#374151" };
            const assetInfo = assetById[ev.asset_id];
            return (
              <tr key={ev.event_id}>
                <td style={styles.td}>
                  <span style={{ padding: "2px 8px", borderRadius: 999, fontSize: 11, fontWeight: 600, background: typeStyle.bg, color: typeStyle.color }}>
                    {typeStyle.label}
                  </span>
                </td>
                <td style={styles.tdMono}>{ev.asset_id ?? ev.asset_name ?? "-"}</td>
                <td style={styles.td}>{assetInfo?.asset_type ?? assetInfo?.type ?? "-"}</td>
                <td style={styles.td}>{formatServerZone(ev.zone ?? assetInfo?.zone) || "-"}</td>
                <td style={styles.td}>{formatDate(getEventTime(ev))}</td>
              </tr>
            );
          })}
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
        <button key={pageNumber} type="button" onClick={() => onPageChange(pageNumber)} style={pageButton(page === pageNumber)}>
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
  return { pageItems: items.slice(start, start + pageSize), currentPage, totalPages };
}

function getCountedAssets(assets) {
  return assets.filter((asset) => asset.observation_status !== "unregistered_asset_candidate");
}

function getCurrentTimelineMetric(timeline, activeScanId, metricName) {
  const points = toList(timeline?.points);
  const point = activeScanId
    ? points.find((item) => (item.run_id ?? item.scan_id) === activeScanId)
    : points.at(-1);
  return point?.metrics?.[metricName];
}

function countChangedAssetIds(assetEvents) {
  return new Set(
    assetEvents.filter((ev) => CHANGE_EVENT_TYPES.has(ev.event_type)).map((ev) => ev.asset_id).filter(Boolean)
  ).size;
}

function buildAssetViolationTrend(assetScanTrend, securityPostureTimeline, currentViolatedAssetCount, activeScanId) {
  const trendByScanId = Object.fromEntries(
    assetScanTrend
      .filter((row) => row.scan_id)
      .map((row) => [row.scan_id, row])
  );
  const timelineRows = toList(securityPostureTimeline?.points)
    .map((point) => {
      const scanId = point.run_id ?? point.scan_id;
      const metrics = point.metrics ?? {};
      const trend = trendByScanId[scanId] ?? {};
      const storedWithViolation = firstNumber(
        metrics.asset_with_violation_count,
        metrics.with_violation_count,
        trend.with_violation && trend.with_violation > 0 ? trend.with_violation : null
      );
      return {
        scan_id: scanId,
        scanned_at: point.created_at ?? point.scanned_at ?? trend.scanned_at,
        month: point.date_label ?? trend.date_label ?? String(point.created_at ?? point.scanned_at ?? trend.scanned_at ?? "").slice(0, 10),
        total: firstNumber(metrics.asset_count, trend.total),
        with_violation: scanId === activeScanId ? currentViolatedAssetCount : storedWithViolation,
      };
    })
    .filter((row) => row.total > 0);

  const rows = timelineRows.length
    ? timelineRows
    : assetScanTrend
      .filter((row) => (row.total ?? 0) > 0)
      .map((row) => ({
        scan_id: row.scan_id,
        scanned_at: row.scanned_at,
        month: row.date_label ?? String(row.scanned_at ?? "").slice(0, 10),
        total: row.total ?? 0,
        with_violation: row.scan_id === activeScanId ? currentViolatedAssetCount : (row.with_violation > 0 ? row.with_violation : null),
      }));

  const currentIndex = activeScanId ? rows.findIndex((row) => row.scan_id === activeScanId) : rows.length - 1;
  const currentPointIndex = currentIndex >= 0 ? currentIndex : rows.length - 1;
  return rows.map((row, index) => ({
    ...row,
    _idx: index,
    with_violation: index === currentPointIndex ? currentViolatedAssetCount : row.with_violation,
  }));
}

function buildAssetChangeTrend(securityPostureTimeline) {
  const rows = toList(securityPostureTimeline?.points)
    .map((point) => {
      const metrics = point.metrics ?? {};
      const changed = firstNumber(metrics.changed_asset_count);
      const created = firstNumber(metrics.new_asset_count, 0);
      const updated = firstNumber(metrics.updated_asset_count, changed);
      const removed = firstNumber(metrics.removed_asset_count, metrics.deleted_asset_count, 0);
      const scannedAt = point.created_at ?? point.scanned_at;
      return {
        scanned_at: scannedAt,
        scan_id: point.run_id ?? point.scan_id,
        date_key: String(scannedAt ?? "").slice(0, 10),
        asset_created: created ?? 0,
        asset_updated: updated ?? 0,
        asset_removed: removed ?? 0,
        hasData: changed != null || created != null || updated != null || removed != null,
      };
    })
    .filter((row) => row.date_key && row.hasData);
  const dayCounts = rows.reduce((counts, row) => {
    counts[row.date_key] = (counts[row.date_key] ?? 0) + 1;
    return counts;
  }, {});
  return rows.map((row, index) => ({
    ...row,
    _idx: index,
    label: dayCounts[row.date_key] > 1 ? formatShortDateTime(row.scanned_at) : formatShortDate(row.scanned_at),
    tooltip_label: `${formatDate(row.scanned_at)} · ${row.scan_id ?? "-"}`,
  }));
}

function buildImpactByAsset(invariantImpact, violations) {
  const impactByAsset = {};
  const addImpact = (assetId, invariantId) => {
    if (!assetId || !invariantId) return;
    if (!impactByAsset[assetId]) impactByAsset[assetId] = new Set();
    impactByAsset[assetId].add(invariantId);
  };

  invariantImpact.forEach((item) => {
    const invariantId = item.invariant_id ?? item.id;
    getImpactAssetIds(item).forEach((assetId) => addImpact(assetId, invariantId));
  });

  violations.forEach((violation) => {
    const invariantId = violation.invariant_id ?? violation.id;
    getViolationAssetIds(violation).forEach((assetId) => addImpact(assetId, invariantId));
  });

  return Object.fromEntries(
    Object.entries(impactByAsset).map(([assetId, invariantIds]) => [assetId, [...invariantIds]])
  );
}

function buildServicesByAsset(services, assets) {
  const assetById = buildAssetMap(assets);
  const serviceById = Object.fromEntries(
    services
      .map((service) => [service.service_id ?? service.id, service])
      .filter(([serviceId]) => serviceId)
  );
  const assetsByVmZone = {};
  assets.forEach((asset) => {
    const key = getVmZoneKey(asset.vm, asset.zone ?? asset.server_zone ?? asset.default_zone);
    if (!key) return;
    if (!assetsByVmZone[key]) assetsByVmZone[key] = [];
    assetsByVmZone[key].push(asset);
  });
  const servicesByAsset = {};
  const addService = (assetId, serviceLabel) => {
    if (!assetId || !serviceLabel) return;
    const asset = assetById[assetId];
    const canonicalAssetId = asset?.asset_id ?? asset?.id ?? assetId;
    if (!servicesByAsset[canonicalAssetId]) servicesByAsset[canonicalAssetId] = new Set();
    servicesByAsset[canonicalAssetId].add(serviceLabel);
  };

  assets.forEach((asset) => {
    const assetId = asset.asset_id ?? asset.id;
    uniqueList(asset.service_ids, asset.all_services, asset.linked_services, asset.observed_services).forEach((serviceId) => {
      addService(assetId, getServiceLabel(serviceById[serviceId] ?? serviceId));
    });
    uniqueList(asset.services, asset.service_names).forEach((service) => {
      addService(assetId, getServiceLabel(serviceById[service] ?? service));
    });
  });

  services.forEach((service) => {
    const label = getServiceLabel(service);
    const directAssetIds = uniqueList(
      service.asset_id,
      service.asset_ids,
      service.owning_asset_id,
      service.owning_asset,
      service.producer_asset_id,
      service.target_asset_id,
      service.host_asset_id
    );
    directAssetIds.forEach((assetId) => addService(assetId, label));
    if (!directAssetIds.length) {
      const vmZoneKey = getVmZoneKey(service.vm, service.zone);
      toList(assetsByVmZone[vmZoneKey]).forEach((asset) => addService(asset.asset_id ?? asset.id, label));
    }
  });

  return Object.fromEntries(
    Object.entries(servicesByAsset).map(([assetId, labels]) => [assetId, [...labels]])
  );
}

function buildAssetMap(assets) {
  const pairs = [];
  toList(assets).forEach((asset) => {
    getAssetKeys(asset).forEach((id) => pairs.push([id, asset]));
  });
  return Object.fromEntries(pairs);
}

function buildAssetIdMap(assets) {
  const pairs = [];
  toList(assets).forEach((asset) => {
    getAssetReferenceKeys(asset).forEach((id) => pairs.push([id, asset]));
  });
  return Object.fromEntries(pairs);
}

function getAssetKeys(asset) {
  if (!asset || typeof asset !== "object") return [];
  return uniqueList(
    asset.asset_id,
    asset.id,
    asset.name,
    asset.asset_name,
    asset.vm,
    asset.hostname,
    asset.resource_id
  );
}

function getAssetReferenceKeys(asset) {
  if (!asset || typeof asset !== "object") return [];
  return uniqueList(asset.asset_id, asset.id, asset.resource_id);
}

function getImpactAssetIds(item) {
  return uniqueList(
    item.affected_registry_asset_ids,
    item.asset_ids,
    item.affected_asset_ids,
    item.asset_id,
    toList(item.affected_assets).map(getAssetId)
  );
}

function getViolationAssetIds(violation) {
  return uniqueList(
    violation.affected_registry_asset_ids,
    violation.asset_ids,
    violation.affected_asset_ids,
    violation.affected_resource_ids,
    violation.invariant_impact?.affected_registry_asset_ids,
    violation.invariant_impact?.asset_ids,
    toList(violation.affected_assets).map(getAssetId),
    toList(violation.assets).map(getAssetId),
    toList(violation.invariant_impact?.affected_assets).map(getAssetId)
  );
}

function getAssetId(asset) {
  if (!asset || typeof asset !== "object") return asset;
  return asset.asset_id ?? asset.id ?? asset.name ?? asset.asset_name ?? asset.vm ?? asset.hostname ?? asset.resource_id;
}

function getServiceLabel(service) {
  if (!service || typeof service !== "object") return service;
  return service.service_name ?? service.name ?? service.service_id ?? service.id;
}

function getVmZoneKey(vm, zone) {
  if (!vm) return "";
  return `${vm}::${formatServerZone(zone) || "-"}`;
}

function getMappedValuesByAsset(map, asset) {
  return uniqueList(getAssetReferenceKeys(asset).flatMap((assetId) => map[assetId] ?? []));
}

function countAssetsByIds(assets, assetIds) {
  return assets.filter((asset) => getAssetReferenceKeys(asset).some((assetId) => assetIds.has(assetId))).length;
}

function firstNumber(...values) {
  return values.find((value) => typeof value === "number" && Number.isFinite(value));
}

function uniqueList(...values) {
  return [...new Set(values.flatMap((value) => toList(value)).filter(Boolean))];
}

function toList(value) {
  if (Array.isArray(value)) return value;
  if (value === null || value === undefined || value === "") return [];
  return [value];
}

function getEventTime(event) {
  return event?.occurred_at ?? event?.created_at ?? event?.timestamp ?? event?.updated_at ?? parseEventTimeFromId(event?.event_id);
}

function eventTimeValue(event) {
  const time = getEventTime(event);
  const date = time ? new Date(time) : null;
  return date && !Number.isNaN(date.getTime()) ? date.getTime() : 0;
}

function parseEventTimeFromId(eventId) {
  const match = String(eventId ?? "").match(/asset-snapshot-(\d{14})/);
  if (!match) return null;
  const [, stamp] = match;
  return `${stamp.slice(0, 4)}-${stamp.slice(4, 6)}-${stamp.slice(6, 8)}T${stamp.slice(8, 10)}:${stamp.slice(10, 12)}:${stamp.slice(12, 14)}Z`;
}

function formatDate(value) {
  if (!value) return "시간 미제공";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ko-KR");
}

function formatShortDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value).slice(0, 10);
  return date.toLocaleDateString("ko-KR", { month: "2-digit", day: "2-digit" });
}

function formatShortDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value).slice(0, 16);
  return date.toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

const styles = {
  summaryGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginBottom: 12 },
  chartGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 12, marginBottom: 12 },
  card: { background: "#fff", border: "1px solid #e4e7ec", borderRadius: 8, padding: 16, marginBottom: 12 },
  label: { display: "block", color: "#667085", fontSize: 12, marginBottom: 7 },
  value: { fontSize: 26, color: "#173b70" },
  cardTitle: { margin: "0 0 12px", fontSize: 14 },
  tableMeta: { display: "flex", justifyContent: "flex-end", color: "#98a2b3", fontSize: 12, marginBottom: 8 },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 12 },
  th: { textAlign: "left", padding: "9px 10px", color: "#667085", borderBottom: "1px solid #e4e7ec" },
  helpHeader: { display: "inline-flex", alignItems: "center", gap: 5 },
  helpBadge: { display: "inline-flex", alignItems: "center", justifyContent: "center", width: 15, height: 15, borderRadius: 999, background: "#eef2f6", color: "#667085", fontSize: 10, fontWeight: 700, cursor: "help" },
  td: { padding: "9px 10px", borderBottom: "1px solid #eef2f6", color: "#344054", verticalAlign: "top" },
  tdMono: { padding: "9px 10px", borderBottom: "1px solid #eef2f6", color: "#344054", fontWeight: 400 },
  metricBarCell: { display: "grid", gridTemplateColumns: "36px 1fr", alignItems: "center", gap: 8, minWidth: 120 },
  metricBarValue: { fontWeight: 700, color: "#173b70" },
  metricBarTrack: { position: "relative", display: "block", height: 8, borderRadius: 999, background: "#eef2f6", overflow: "hidden" },
  metricBarFill: { position: "absolute", inset: "0 auto 0 0", borderRadius: 999 },
  pagination: { display: "flex", justifyContent: "center", alignItems: "center", gap: 6, marginTop: 14, flexWrap: "wrap" },
  note: { margin: "0 0 12px", fontSize: 11, color: "#b0b7c3", lineHeight: 1.5 },
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
