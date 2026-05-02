import { useState } from "react";
import KpiCards from "../components/KpiCards";
import ViolationSection from "../components/ViolationSection";
import AttackSection from "../components/AttackSection";
import PentestSection from "../components/PentestSection";
import DefenseSection from "../components/DefenseSection";
import InvariantSection from "../components/InvariantSection";
import AssetSection from "../components/AssetSection";
import {
  scanSummary, violations,
  attackChains, mitreMapping, pentestResults, coverage, scoreHistory, remediations,
  assets, assetHistory, assetEvents, assetPolicies, softwareAssets, credentialAssets, apiAssets,
} from "../data/dummyData";


// 네비게이션 메뉴 구성 — 각 메뉴는 보여주는 섹션이 다름 (id는 내부 식별자, label은 화면에 보이는 이름, icon은 메뉴 아이콘, sections는 해당 메뉴에서 보여주는 섹션들)
const NAV_ITEMS = [
  { id: "vuln",      label: "취약점 발견 현황",      icon: "⚠",  sections: ["kpi", "violation", "attack"] },
  { id: "invariant", label: "불변식 목록",            icon: "📋", sections: ["invariant"] },
  { id: "pentest",   label: "모의침투 결과",          icon: "🔓", sections: ["kpi", "pentest"] },
  { id: "defense",   label: "방어 방안 및 보안 수준", icon: "🛡", sections: ["defense"] },
  { id: "asset",     label: "자산 관리",              icon: "🖥", sections: ["asset"] },
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

export default function Dashboard() {
  /* 대시보드가 관리하는 상태들 */ 
  const [activeNav, setActiveNav] = useState("vuln");        // 현재 선택된 네비게이션 메뉴 (기본값은 "취약점 발견 현황")
  const [activeFilter, setActiveFilter] = useState("전체");  // 현재 선택된 필터 (기본값은 "전체")
  const current = NAV_ITEMS.find((n) => n.id === activeNav); // 현재 네비게이션 메뉴에 해당하는 객체 (예: { id: "vuln", label: "취약점 발견 현황", ... })
  
  /* 네비게이션 메뉴 변경 핸들러 */
  const handleNavChange = (id) => {
    setActiveNav(id);
    setActiveFilter("전체");
  };
  
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

        {/* 스캔 정보 */}
        <div style={{ padding: "12px 20px", borderBottom: "0.5px solid rgba(255,255,255,0.08)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#1D9E75", display: "inline-block" }} />
            <span style={{ fontSize: 11, color: "#1D9E75", fontWeight: 500 }}>스캔 완료</span>
          </div>
          <p style={{ fontSize: 10, color: "#73726c", margin: "4px 0 0" }}>{scanSummary.scan_id}</p>
          <p style={{ fontSize: 10, color: "#73726c", margin: "2px 0 0" }}>
            {new Date(scanSummary.scanned_at).toLocaleDateString("ko-KR")}
          </p>
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

        {/* 페이지 헤더 */}
        <div style={{ marginBottom: 16 }}>
          <p style={{ fontSize: 11, color: "#73726c", margin: "0 0 4px" }}>
            Argos Security / {SECTION_LABEL[activeNav]}
          </p>
          <p style={{ fontSize: 20, fontWeight: 500, margin: 0 }}>
            {SECTION_LABEL[activeNav]}
          </p>
        </div>

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
        
        {/* 각 네비게이션 별 보여주는 섹션들 */} 
        
        {current.sections.includes("kpi") && (
          <div style={{ marginBottom: 32 }}>
            <p style={sectionLabel}>전체 현황</p>
            <KpiCards
              summary={scanSummary.summary}
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
            <InvariantSection />
          </div>
)}

        {current.sections.includes("pentest") && (
          <div style={{ marginBottom: 32 }}>
            <PentestSection pentestResults={pentestResults} />
          </div>
        )}

        {current.sections.includes("defense") && (
          <div style={{ marginBottom: 32 }}>
            <DefenseSection coverage={coverage} scoreHistory={scoreHistory} remediations={remediations} />
          </div>
        )}

        {current.sections.includes("asset") && (
          <div style={{ marginBottom: 32 }}>
            <AssetSection
              assets={assets}
              assetHistory={assetHistory}
              assetEvents={assetEvents}
              assetPolicies={assetPolicies}
              softwareAssets={softwareAssets}
              credentialAssets={credentialAssets}
              apiAssets={apiAssets} />
          </div>
        )}

      </main>
    </div>
  );
}

const sectionLabel = {
  fontSize: 11, fontWeight: 500, color: "#73726c",
  textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 10,
};
