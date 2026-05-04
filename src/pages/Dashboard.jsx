import { useState, useEffect } from "react";
import KpiCards from "../components/KpiCards";
import ViolationSection from "../components/ViolationSection";
import AttackSection from "../components/AttackSection";
import PentestSection from "../components/PentestSection";
import DefenseSection from "../components/DefenseSection";
import InvariantSection from "../components/InvariantSection";
import AssetSection from "../components/AssetSection";
import { fetchScanList, fetchScanDetails } from "../services/scanService";
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
};

// 보안 점수에 따른 색상 반환
function scoreColor(score) {
  if (score >= 70) return "#1D9E75";
  if (score >= 50) return "#E8A838";
  return "#E05A5A";
}

export default function Dashboard() {
  /* 대시보드가 관리하는 상태들 */
  const [activeNav, setActiveNav]               = useState("vuln");        // 현재 선택된 네비게이션 메뉴 (기본값은 "취약점 발견 현황")
  const [activeFilter, setActiveFilter]         = useState("전체");        // 현재 선택된 필터 (기본값은 "전체")
  const [scanListData, setScanListData]         = useState([]);             // 전체 스캔 목록 (집계 지표 포함)
  const [selectedScanId, setSelectedScanId]     = useState(null);           // 현재 선택된 스캔 ID
  const [currentDetails, setCurrentDetails]     = useState(null);           // 선택된 스캔의 세부 데이터
  const [loadingDetails, setLoadingDetails]     = useState(false);          // 세부 데이터 로딩 중 여부
  const current = NAV_ITEMS.find((n) => n.id === activeNav); // 현재 네비게이션 메뉴에 해당하는 객체 (예: { id: "vuln", label: "취약점 발견 현황", ... })

  // 스캔 목록 초기 로드 — 마운트 시 한 번만 실행, 최신 스캔을 기본 선택
  useEffect(() => {
    fetchScanList().then((list) => {
      setScanListData(list);
      const latestId = list[list.length - 1]?.scan_id;
      if (latestId) setSelectedScanId(latestId);
    });
  }, []);

  // 선택된 스캔의 세부 데이터 로드 — selectedScanId 변경 시마다 실행
  // 백엔드 연동 후에는 fetchScanDetails 내부만 교체하면 됨
  useEffect(() => {
    if (!selectedScanId) return;
    setLoadingDetails(true);
    fetchScanDetails(selectedScanId).then((details) => {
      setCurrentDetails(details);
      setLoadingDetails(false);
    });
  }, [selectedScanId]);

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
  const violations   = currentDetails?.violations ?? [];

  /* */
  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>

      {/* 사이드바 */}
      <aside style={{
        width: 220,
        minHeight: "100vh",         // 사이드바가 화면 전체 높이를 차지하도록 설정
        background: "#042C53",
        display: "flex",
        flexDirection: "column",
        flexShrink: 0,              // 사이드바가 축소되지 않도록 설정
        position: "sticky", top: 0, // 스크롤 시에도 사이드바가 화면 상단에 고정되도록 설정
        height: "100vh",
      }}>
        {/* 로고 */}
        <div style={{ padding: "24px 20px 20px", borderBottom: "0.5px solid rgba(255,255,255,0.08)" }}>
          <p style={{ fontSize: 13, fontWeight: 500, color: "#fff", margin: 0, letterSpacing: "0.04em" }}>ARGOS</p>
          <p style={{ fontSize: 10, color: "#73726c", margin: "2px 0 0" }}>Security Dashboard</p>
        </div>

        {/* 현재 선택된 스캔 정보 — 점검 관리 페이지에서 스캔을 선택할 수 있음 */}
        <div style={{ padding: "12px 20px", borderBottom: "0.5px solid rgba(255,255,255,0.08)" }}>
          <p style={{ fontSize: 10, fontWeight: 500, color: "#73726c", textTransform: "uppercase", letterSpacing: "0.07em", margin: "0 0 6px" }}>
            현재 스캔
          </p>
          {selectedScan ? (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 2 }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#1D9E75", display: "inline-block", flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: "#fff", fontWeight: 500 }}>{selectedScan.scan_id}</span>
              </div>
              <p style={{ fontSize: 10, color: "#73726c", margin: "0 0 2px 14px" }}>
                {new Date(selectedScan.scanned_at).toLocaleDateString("ko-KR")}
              </p>
              <p style={{ fontSize: 10, margin: "0 0 0 14px" }}>
                <span style={{ color: scoreColor(selectedScan.metrics.score), fontWeight: 600 }}>
                  {selectedScan.metrics.score}점
                </span>
                <span style={{ color: "#73726c" }}> · {selectedScan.metrics.total_violations}건</span>
              </p>
            </>
          ) : (
            <p style={{ fontSize: 10, color: "#73726c", margin: 0 }}>로딩 중...</p>
          )}
        </div>

        {/* 네비게이션 */}
        <nav style={{ padding: "12px", flex: 1 }}>
          {NAV_ITEMS.map((item) => {
            const isActive = activeNav === item.id; // 현재 메뉴가 선택된 메뉴인지 확인
            return (
              <button key={item.id} onClick={() => handleNavChange(item.id)} style={{
                width: "100%", display: "flex", alignItems: "center", gap: 10,
                padding: "10px 12px", borderRadius: 8, border: "none", cursor: "pointer",
                background: isActive ? "#185FA5" : "transparent",
                color: isActive ? "#fff" : "#888780",
                fontSize: 12, fontWeight: isActive ? 500 : 400,
                marginBottom: 4, textAlign: "left",
              }}>
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
            border: "0.5px solid rgba(255,255,255,0.15)", background: "#f4f4f4",
            color: "#888780", fontSize: 11, cursor: "pointer",
          }}>
            보고서 출력
          </button>
        </div>
      </aside>

      {/* 메인 콘텐츠 */}
      <main style={{ flex: 1, minWidth: 0, padding: "32px 32px 64px" }}>

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

        {/* 세부 데이터 없음 안내 — SCAN-0042~0045처럼 더미 데이터가 없는 스캔 선택 시 표시 */}
        {!loadingDetails && selectedScan && !currentDetails && (
          <div style={{ background: "#f5f5f3", borderRadius: 12, padding: "32px 24px", textAlign: "center", marginBottom: 24 }}>
            <p style={{ fontSize: 13, fontWeight: 500, color: "#1a1a18", margin: "0 0 6px" }}>
              {selectedScan.scan_id} 세부 데이터를 불러올 수 없습니다
            </p>
            <p style={{ fontSize: 11, color: "#73726c", margin: "0 0 20px" }}>
              이 스캔은 집계 지표만 제공됩니다. 백엔드 연동 후 전체 데이터를 조회할 수 있습니다.
            </p>
            <div style={{ display: "inline-flex", gap: 12 }}>
              {[
                { label: "보안 점수",    value: selectedScan.metrics.score,              unit: "점" },
                { label: "총 취약점",    value: selectedScan.metrics.total_violations,   unit: "건" },
                { label: "Critical/High", value: selectedScan.metrics.critical_high,     unit: "건" },
                { label: "패치 적용률",  value: selectedScan.metrics.patch_rate,         unit: "%" },
              ].map((m) => (
                <div key={m.label} style={{ background: "#fff", borderRadius: 8, padding: "12px 20px", minWidth: 90 }}>
                  <p style={{ fontSize: 10, color: "#73726c", margin: "0 0 4px" }}>{m.label}</p>
                  <p style={{ fontSize: 20, fontWeight: 500, color: "#1a1a18", margin: 0 }}>
                    {m.value}<span style={{ fontSize: 11, marginLeft: 2 }}>{m.unit}</span>
                  </p>
                </div>
              ))}
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
            />
          </div>
        )}

        {/* 각 네비게이션 별 보여주는 섹션들 — currentDetails가 있을 때만 렌더링 */}

        {!loadingDetails && currentDetails && !current.sections.includes("scan") && (
          <>
            {/* 전역 필터 탭 — 취약점 발견 현황 페이지에서만 표시 */}
            {activeNav === "vuln" && (
              <div style={{ display: "flex", gap: 6, marginBottom: 24 }}>
                {FILTER_TABS.map((tab) => {                    // 각 필터 탭에 대해 취약점 수 계산하고 버튼 생성
                  const count = tab.id === "전체"              // 취약점 수 count 계산
                    ? violations.length
                    : violations.filter((v) => v.invariant_source === tab.id).length;
                  const isActive = activeFilter === tab.id;   // 현재 필터가 선택된 필터인지 확인
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
                  summary={currentDetails.summary}
                  violations={violations}
                  activeFilter={activeNav === "vuln" ? activeFilter : "전체"}
                  attackChains={currentDetails.attackChains}
                  pentestResults={currentDetails.pentestResults} />
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
                  attackChains={currentDetails.attackChains}
                  mitreMapping={currentDetails.mitreMapping}
                  violations={violations}
                  activeFilter={activeFilter} />
              </div>
            )}

            {current.sections.includes("invariant") && (
              <div style={{ marginBottom: 32 }}>
                <InvariantSection />
              </div>
            )}

            {current.sections.includes("pentest") && (
              <div style={{ marginBottom: 32 }}>
                <PentestSection pentestResults={currentDetails.pentestResults} />
              </div>
            )}

            {current.sections.includes("defense") && (
              <div style={{ marginBottom: 32 }}>
                <DefenseSection
                  coverage={currentDetails.coverage}
                  scoreHistory={scanListData.map((s) => ({
                    scan_id: s.scan_id,
                    scanned_at: s.scanned_at,
                    score: s.metrics.score,
                  }))}
                  remediations={currentDetails.remediations} />
              </div>
            )}

            {current.sections.includes("asset") && (
              <div style={{ marginBottom: 32 }}>
                <AssetSection
                  assets={currentDetails.assets}
                  assetHistory={currentDetails.assetHistory}
                  assetEvents={currentDetails.assetEvents}
                  assetPolicies={currentDetails.assetPolicies}
                  softwareAssets={currentDetails.softwareAssets}
                  credentialAssets={currentDetails.credentialAssets}
                  apiAssets={currentDetails.apiAssets} />
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
