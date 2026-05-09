import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import KpiCards from "../components/KpiCards";
import ViolationSection from "../components/ViolationSection";
import AttackSection from "../components/AttackSection";
import PentestSection from "../components/PentestSection";
import DefenseSection from "../components/DefenseSection";
import InvariantSection from "../components/InvariantSection";
import AssetSection from "../components/AssetSection";
import { fetchScanList, fetchScanDetails, USE_MOCK } from "../services/scanService";
import { invariants as localInvariants } from "../data/invariantsData";
import ScanSection from "../components/ScanSection";


// 네비게이션 메뉴 구성 — 각 메뉴는 보여주는 섹션이 다름 (id는 내부 식별자, label은 화면에 보이는 이름, icon은 메뉴 아이콘, sections는 해당 메뉴에서 보여주는 섹션들)
const NAV_ITEMS = [
  { id: "vuln",      label: "취약점 발견 현황",      icon: "⚠",  sections: ["kpi", "violation", "attack"] },
  { id: "invariant", label: "불변식 목록",            icon: "📋", sections: ["invariant"] },
  { id: "pentest",   label: "모의침투 결과",          icon: "🔓", sections: ["kpi", "pentest"] },
  { id: "defense",   label: "방어 방안 및 보안 수준", icon: "🛡", sections: ["defense"] },
  { id: "asset",     label: "자산 관리",              icon: "🖥", sections: ["asset"] },
  { id: "scan",      label: "점검 관리",              icon: "🔍", sections: ["scan"] },
];

// 취약점 발견 현황 페이지에서 보여주는 필터 탭 구성 - 전체, 고정 불변식, 가변 불변식으로 나뉘며, 고정/가변 불변식은 취약점의 출처(invariant_source)에 따라 구분
const FILTER_TABS = [
  { id: "전체",     label: "전체" },
  { id: "fixed",    label: "고정 불변식" },
  { id: "variable", label: "가변 불변식" },
];

// 각 네비게이션 메뉴에 대응하는 섹션 라벨 - 페이지 헤더에 사용
const SECTION_LABEL = {
  vuln:     "취약점 발견 현황",
  invariant: "불변식 목록",
  pentest:  "모의침투 결과",
  defense:  "방어 방안 및 보안 수준",
  asset:    "자산 관리",
  scan:     "점검 관리",
};

// 보안 점수에 따른 색상 반환
function scoreColor(score) {
  if (score >= 70) return "#1D9E75";
  if (score >= 50) return "#E8A838";
  return "#E05A5A";
}

export default function Dashboard() {
  /* 대시보드가 관리하는 상태들 */
  const [activeNav, setActiveNav]           = useState("vuln");   // 현재 선택된 네비게이션 메뉴
  const [activeFilter, setActiveFilter]     = useState("전체");   // 현재 선택된 필터
  const [selectedScanId, setSelectedScanId] = useState(null);     // 현재 선택된 스캔 ID
  const [hoveredNav, setHoveredNav]         = useState(null);     // hover 중인 메뉴 id
  const current = NAV_ITEMS.find((n) => n.id === activeNav);

  // 스캔 목록 조회 — React Query가 캐싱·재시도를 자동으로 처리
  const {
    data: scanListData = [],
    isLoading: loadingList,
    error: listError,
    refetch: refetchScanList,
  } = useQuery({
    queryKey: ["scans"],
    queryFn: fetchScanList,
  });

  // 스캔 목록이 로드되면 scanned_at 기준으로 가장 최신 스캔을 자동 선택
  // 배열 마지막 항목이 아닌 날짜 정렬로 선택 — 백엔드 응답 순서에 무관하게 동작
  useEffect(() => {
    if (scanListData.length > 0 && !selectedScanId) {
      const latest = [...scanListData].sort(
        (a, b) => new Date(b.scanned_at) - new Date(a.scanned_at)
      )[0];
      if (latest) setSelectedScanId(latest.scan_id);
    }
  }, [scanListData, selectedScanId]);

  // 선택된 스캔의 세부 데이터 조회 — selectedScanId가 있을 때만 실행
  const {
    data: currentDetails,
    isLoading: loadingDetails,
    error: detailsError,
  } = useQuery({
    queryKey: ["scan-details", selectedScanId],
    queryFn: () => fetchScanDetails(selectedScanId),
    enabled: !!selectedScanId,
  });

  const error = listError || detailsError;

  /* 네비게이션 메뉴 변경 핸들러 */
  const handleNavChange = (id) => {
    setActiveNav(id);
    setActiveFilter("전체");
  };

  /* 스캔 선택 핸들러 */
  const handleScanSelect = (scanId) => {
    if (scanId === selectedScanId) return;
    setSelectedScanId(scanId);
  };

  const selectedScan = scanListData.find((s) => s.scan_id === selectedScanId);

  // currentDetails가 없을 때 빈 기본값 — 컴포넌트 구조는 항상 렌더링
  const violations        = currentDetails?.violations      ?? [];
  const attackChains      = currentDetails?.attackChains    ?? [];
  const mitreMapping      = currentDetails?.mitreMapping    ?? [];
  const pentestResults    = currentDetails?.pentestResults  ?? [];
  const coverage          = currentDetails?.coverage        ?? {};
  const remediations      = currentDetails?.remediations    ?? [];
  const assets            = currentDetails?.assets          ?? [];
  const services          = currentDetails?.services        ?? [];
  const evidenceEvents    = currentDetails?.evidenceEvents  ?? [];
  const invariantImpact   = currentDetails?.invariantImpact ?? [];
  const summary           = currentDetails?.summary         ?? { total_violations: 0, critical_high: 0, attack_chains: 0 };
  // mock 모드에서는 로컬 불변식 데이터를 기본값으로, 실제 API 모드에서는 빈 배열
  const invariantsData    = currentDetails?.invariants      ?? (USE_MOCK ? localInvariants : []);

  // 자산 추이: scan_asset_snapshot JOIN 결과를 scanListData에서 스캔 단위로 파생
  // 활성 테이블(scans + scan_asset_snapshot) 기반
  // new_assets: 직전 스캔 대비 asset_count 증가분 (scan_asset_snapshot에 신규 자산 컬럼 없으므로 파생)
  const _sortedScans = [...scanListData].sort((a, b) => new Date(a.scanned_at) - new Date(b.scanned_at));
  const assetHistory = _sortedScans.map((s, i) => {
    const prev       = _sortedScans[i - 1];
    const new_assets = prev ? Math.max(0, (s.asset_count ?? 0) - (prev.asset_count ?? 0)) : 0;
    return {
      date:           new Date(s.scanned_at).toLocaleDateString("ko-KR", { month: "short", day: "numeric" }),
      scan_id:        s.scan_id,
      total:          s.asset_count           ?? 0,
      unregistered:   s.unregistered_count     ?? 0,
      with_violation: s.with_violation_count   ?? 0,
      new_assets,
    };
  });

  // 비활성 테이블 관련 props — 주석으로 보존 (데이터 없어도 화면 동작)
  // const assetEvents      = currentDetails?.assetEvents      ?? [];  // [비활성] asset_events
  // const assetPolicies    = currentDetails?.assetPolicies    ?? [];  // [비활성] invariant_impact
  // const softwareAssets   = currentDetails?.softwareAssets   ?? [];  // [비활성] software_assets
  // const credentialAssets = currentDetails?.credentialAssets ?? [];  // [비활성] credential_assets
  // const apiAssets        = currentDetails?.apiAssets        ?? [];  // [비활성] api_assets

  /* */
  return (
    <div style={{ display: "flex", minHeight: "100vh", background: "#F8FAFC" }}>

      {/* 사이드바 */}
      <aside style={{
        width: 220,
        minHeight: "100vh",
        background: "#0F172A",
        display: "flex",
        flexDirection: "column",
        flexShrink: 0,
        position: "sticky", top: 0,
        height: "100vh",
      }}>
        {/* 로고 */}
        <div style={{ padding: "24px 20px 20px", borderBottom: "0.5px solid rgba(255,255,255,0.08)" }}>
          <p style={{ fontSize: 13, fontWeight: 500, color: "#fff", margin: 0, letterSpacing: "0.04em" }}>ARGOS</p>
          <p style={{ fontSize: 10, color: "#9CA3AF", margin: "2px 0 0" }}>Security Dashboard</p>
        </div>

        {/* 현재 선택된 스캔 정보 */}
        <div style={{ padding: "12px 20px", borderBottom: "0.5px solid rgba(255,255,255,0.08)" }}>
          <p style={{ fontSize: 10, fontWeight: 500, color: "#9CA3AF", textTransform: "uppercase", letterSpacing: "0.07em", margin: "0 0 6px" }}>
            현재 스캔
          </p>
          {loadingList ? (
            <p style={{ fontSize: 10, color: "#9CA3AF", margin: 0 }}>로딩 중...</p>
          ) : listError ? (
            <p style={{ fontSize: 10, color: "#E05A5A", margin: 0 }}>불러오기 실패</p>
          ) : selectedScan ? (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 2 }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#1D9E75", display: "inline-block", flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: "#fff", fontWeight: 500 }}>{selectedScan.scan_id}</span>
              </div>
              <p style={{ fontSize: 10, color: "#9CA3AF", margin: "0 0 2px 14px" }}>
                {new Date(selectedScan.scanned_at).toLocaleDateString("ko-KR")}
              </p>
              <p style={{ fontSize: 10, margin: "0 0 0 14px" }}>
                <span style={{ color: scoreColor(selectedScan.score), fontWeight: 600 }}>
                  {selectedScan.score}점
                </span>
                <span style={{ color: "#9CA3AF" }}> · {selectedScan.total_violations}건</span>
              </p>
            </>
          ) : null}
        </div>

        {/* 네비게이션 */}
        <nav style={{ padding: "12px", flex: 1 }}>
          {NAV_ITEMS.map((item) => {
            const isActive  = activeNav === item.id;
            const isHovered = hoveredNav === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleNavChange(item.id)}
                onMouseEnter={() => setHoveredNav(item.id)}
                onMouseLeave={() => setHoveredNav(null)}
                style={{
                  width: "100%", display: "flex", alignItems: "center", gap: 10,
                  padding: "10px 12px", borderRadius: 8, border: "none", cursor: "pointer",
                  background: isActive ? "#3B82F6" : isHovered ? "rgba(255,255,255,0.06)" : "transparent",
                  color: isActive ? "#FFFFFF" : "#9CA3AF",
                  fontSize: 12, fontWeight: isActive ? 500 : 400,
                  marginBottom: 4, textAlign: "left",
                  transition: "background 0.15s",
                }}
              >
                <span style={{ fontSize: 14 }}>{item.icon}</span>
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* 보고서 버튼 */}
        <div style={{ padding: "16px 12px", borderTop: "0.5px solid rgba(255,255,255,0.08)" }}>
          <button style={{
            width: "100%", padding: "8px 0", borderRadius: 8,
            border: "0.5px solid rgba(255,255,255,0.12)", background: "transparent",
            color: "#9CA3AF", fontSize: 11, cursor: "pointer",
          }}>
            보고서 출력
          </button>
        </div>
      </aside>

      {/* 메인 콘텐츠 */}
      <main style={{ flex: 1, minWidth: 0, padding: "32px 32px 64px", background: "#F8FAFC" }}>

        {/* 페이지 헤더 — 우측에 현재 선택된 스캔 ID와 날짜 표시 */}
        <div style={{ marginBottom: 16, display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
          <div>
            <p style={{ fontSize: 11, color: "#73726c", margin: "0 0 4px" }}>
              Argos Security / {SECTION_LABEL[activeNav]}
            </p>
            <p style={{ fontSize: 20, fontWeight: 500, margin: 0 }}>
              {SECTION_LABEL[activeNav]}
            </p>
          </div>
          {selectedScan && (
            <div style={{ textAlign: "right" }}>
              <p style={{ fontSize: 11, fontWeight: 500, color: "#1a1a18", margin: "0 0 2px" }}>{selectedScan.scan_id}</p>
              <p style={{ fontSize: 10, color: "#73726c", margin: 0 }}>
                {new Date(selectedScan.scanned_at).toLocaleDateString("ko-KR", { year: "numeric", month: "long", day: "numeric" })} 기준
              </p>
            </div>
          )}
        </div>

        {/* API 오류 안내 */}
        {error && (
          <div style={{ background: "#FEF2F2", border: "0.5px solid #FECACA", borderRadius: 10, padding: "12px 16px", marginBottom: 20, display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 16 }}>⚠</span>
            <div>
              <p style={{ fontSize: 13, fontWeight: 500, color: "#991B1B", margin: "0 0 2px" }}>데이터를 불러오지 못했습니다</p>
              <p style={{ fontSize: 11, color: "#B91C1C", margin: 0 }}>{error.message}</p>
            </div>
          </div>
        )}

        {/* 로딩 중 */}
        {loadingDetails && (
          <div style={{ padding: "48px 0", textAlign: "center" }}>
            <p style={{ fontSize: 13, color: "#73726c", margin: 0 }}>스캔 데이터를 불러오는 중...</p>
          </div>
        )}

        {/* 점검 관리 페이지 — currentDetails 없이도 독립적으로 렌더링 */}
        {current.sections.includes("scan") && (
          <div style={{ marginBottom: 32 }}>
            <ScanSection
              scanList={scanListData}
              selectedScanId={selectedScanId}
              onSelectScan={handleScanSelect}
              onRefresh={refetchScanList}
            />
          </div>
        )}

        {/* 각 섹션 — 데이터 없어도 구조는 항상 렌더링, 로딩 중일 때만 숨김 */}

        {!loadingDetails && !current.sections.includes("scan") && (
          <>
            {/* 전역 필터 탭 — 취약점 발견 현황 페이지에서만 표시 */}
            {activeNav === "vuln" && (
              <div style={{ display: "flex", gap: 6, marginBottom: 24 }}>
                {FILTER_TABS.map((tab) => {
                  const count = tab.id === "전체"
                    ? violations.length
                    : violations.filter((v) => v.invariant_source === tab.id).length;
                  const isActive = activeFilter === tab.id;
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setActiveFilter(tab.id)}
                      style={{
                        padding: "5px 14px", borderRadius: 99, border: "0.5px solid",
                        fontSize: 12, cursor: "pointer",
                        borderColor: isActive ? "#185FA5" : "rgba(0,0,0,0.12)",
                        background: isActive ? "#185FA5" : "transparent",
                        color: isActive ? "#fff" : "#73726c",
                        fontWeight: isActive ? 500 : 400,
                      }}
                    >
                      {tab.label}
                      <span style={{
                        marginLeft: 6, fontSize: 10,
                        background: isActive ? "rgba(255,255,255,0.25)" : "rgba(0,0,0,0.06)",
                        padding: "1px 6px", borderRadius: 99,
                        color: isActive ? "#fff" : "#73726c",
                      }}>
                        {count}
                      </span>
                    </button>
                  );
                })}
              </div>
            )}

            {current.sections.includes("kpi") && (
              <div style={{ marginBottom: 32 }}>
                <p style={sectionLabel}>전체 현황</p>
                <KpiCards
                  summary={summary}
                  violations={violations}
                  activeFilter={activeNav === "vuln" ? activeFilter : "전체"}
                  attackChains={attackChains}
                  pentestResults={pentestResults} />
              </div>
            )}

            {current.sections.includes("violation") && (
              <div style={{ marginBottom: 32 }}>
                <ViolationSection
                  violations={violations}
                  activeFilter={activeFilter} />
              </div>
            )}

            {current.sections.includes("attack") && (
              <div style={{ marginBottom: 32 }}>
                <AttackSection
                  attackChains={attackChains}
                  mitreMapping={mitreMapping}
                  violations={violations}
                  activeFilter={activeFilter} />
              </div>
            )}

            {current.sections.includes("invariant") && (
              <div style={{ marginBottom: 32 }}>
                <InvariantSection invariants={invariantsData} />
              </div>
            )}

            {current.sections.includes("pentest") && (
              <div style={{ marginBottom: 32 }}>
                <PentestSection pentestResults={pentestResults} scanId={selectedScanId} attackChains={attackChains} />
              </div>
            )}

            {current.sections.includes("defense") && (
              <div style={{ marginBottom: 32 }}>
                <DefenseSection
                  coverage={coverage}
                  scoreHistory={scanListData.map((s) => ({
                    scan_id: s.scan_id,
                    scanned_at: s.scanned_at,
                    score: s.score,
                  }))}
                  remediations={remediations} />
              </div>
            )}

            {current.sections.includes("asset") && (
              <div style={{ marginBottom: 32 }}>
                <AssetSection
                  assets={assets}
                  assetHistory={assetHistory}
                  services={services}
                  evidenceEvents={evidenceEvents}
                  invariantImpact={invariantImpact}
                  // 비활성 props (schema.sql 주석 처리된 테이블 — 필요 시 활성화)
                  // assetEvents={assetEvents}
                  // assetPolicies={assetPolicies}
                  // softwareAssets={softwareAssets}
                  // credentialAssets={credentialAssets}
                  // apiAssets={apiAssets}
                />
              </div>
            )}
          </>
        )}

      </main>
    </div>
  );
}

const sectionLabel = {
  fontSize: 11, fontWeight: 500, color: "#73726c",
  textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 10,
};
