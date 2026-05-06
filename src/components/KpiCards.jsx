/*
 * 대시보드 상단에 [전체 현황]을 보여주는 kpi 카드 컴포넌트 
 *
 * - 취약점 현황, 공격 체인 수, 모의침투 성공 시나리오 수 등을 표시
 * - activeFilter에 따라 취약점 현황이 필터링되어 카드 수치가 업데이트됨
 * - summary 데이터는 scanSummary.summary에서 받아옴
 * - violations 데이터는 Dashboard에서 props로 전달받음
 * - activeFilter는 Dashboard의 상태로 관리되며, "전체", "fixed", "variable" 등의 값을 가질 수 있음
 * - 카드 디자인은 간단한 그리드 레이아웃과 색상으로 구분하여 시각적으로 강조
 * - 각 카드에는 label과 value가 명확히 표시되어야 함
 * - 향후 확장성을 고려하여 카드 항목은 배열로 관리하고 map으로 렌더링하도록 구현
 */

export default function KpiCards({ summary, violations, activeFilter, attackChains, pentestResults }) {
  /* 데이터 준비
   * - violations 데이터가 존재할 때만 activeFilter에 따라 필터링하여 total과 criticalHigh 계산
   * - activeFilterrk "전체"이거나 v.invariant_source가 activeFilter(fixed||variable)와 같은 경우만 필터링 */
  const filtered = violations
    ? violations.filter((v) => activeFilter === "전체" || v.invariant_source === activeFilter)
    : null;

  /* 불변식 위반 총 수와 Critical/High 계산
   * - total은 필터링된 데이터의 길이 또는 summary에서 받아온 total_violations 값
   * - criticalHigh는 필터링된 데이터 중 severity가 Critical 또는 High인 항목의 수 또는 summary에서 받아온 critical_high 값 */
  const total = filtered ? filtered.length : summary.total_violations;
  const criticalHigh = filtered
    ? filtered.filter((v) => v.severity === "Critical" || v.severity === "High").length
    : summary.critical_high;

  const chainCount = attackChains ? attackChains.length : summary.attack_chains;
  const pentestSuccess = (pentestResults ?? []).filter((r) => r.overall_verdict === "reproduced").length;

  const cards = [
    { label: "총 불변식 위반", value: total, color: "#0C447C" },
    { label: "Critical / High", value: criticalHigh, color: "#0C447C" },
    { label: "공격 체인 수", value: chainCount, color: "#185FA5" },
    { label: "침투 성공 시나리오", value: pentestSuccess, color: "#185FA5" },
  ];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 24 }}>
      {cards.map((card) => (
        <div key={card.label} style={{ background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: "14px 16px" }}>
          <p style={{ fontSize: 12, color: "#73726c", marginBottom: 6 }}>{card.label}</p>
          <p style={{ fontSize: 24, fontWeight: 500, color: card.color, margin: 0 }}>{card.value}</p>
        </div>
      ))}
    </div>
  );
}
