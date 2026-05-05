import { useState } from "react";
import {
  LineChart, Line, BarChart, Bar,
  XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer, ReferenceLine,
} from "recharts";

// ── 상수 ─────────────────────────────────────────────────────────────────────

const STATUS_STYLE = {
  취약: { bg: "#EEF4FD", text: "#185FA5" },
  정상: { bg: "#E1F5EE", text: "#085041" },
};

const PATCH_STYLE = {
  적용완료: { bg: "#E1F5EE", text: "#085041" },
  미적용:   { bg: "#EEF4FD", text: "#0C447C" },
  지연:     { bg: "#E6F1FB", text: "#185FA5" },
};

const SEV_STYLE = {
  Critical: { bg: "#E6F1FB", text: "#0C447C" },
  High:     { bg: "#EEF4FD", text: "#185FA5" },
  Medium:   { bg: "#F0F6FE", text: "#378ADD" },
  Low:      { bg: "#E1F5EE", text: "#085041" },
};

const POL_SEV_STYLE = {
  Critical: { border: "#0C447C", bg: "#E6F1FB", text: "#0C447C" },
  High:     { border: "#185FA5", bg: "#EEF4FD", text: "#185FA5" },
  Medium:   { border: "#378ADD", bg: "#F0F6FE", text: "#378ADD" },
};

const EVT_TYPE_STYLE = {
  신규장비:    { bg: "#E6F1FB", text: "#0C447C" },
  정책위반:    { bg: "#EEF4FD", text: "#185FA5" },
  비인가접속:  { bg: "#E6F1FB", text: "#0C447C" },
  네트워크이동: { bg: "#f1efea", text: "#73726c" },
};

// 자격증명 상태별 스타일
const CRED_STATUS_STYLE = {
  위험:    { bg: "#E6F1FB", text: "#0C447C" },
  취약:    { bg: "#EEF4FD", text: "#185FA5" },
  만료임박: { bg: "#FFF8E1", text: "#8B6914" },
  정상:    { bg: "#E1F5EE", text: "#085041" },
};

// 자격증명 보관 방식별 스타일 — HSM이 가장 안전, 파일시스템이 가장 위험
const STORAGE_STYLE = {
  HSM:      { bg: "#E1F5EE", text: "#085041" },
  파일시스템: { bg: "#E6F1FB", text: "#0C447C" },
  환경변수:  { bg: "#EEF4FD", text: "#185FA5" },
  DB:       { bg: "#F0F6FE", text: "#378ADD" },
  "-":      { bg: "#f1efea", text: "#73726c" },
};

const SEGMENT_COLOR = { DMZ: "#185FA5", 내부망: "#378ADD", 폐쇄망: "#85B7EB" };
const TYPES         = ["전체", "서버", "PC", "IoT", "네트워크 장비"];
const STATUSES      = ["전체", "취약", "정상"];

function deriveAssetStatus(asset) {
  const needsEdrAv = asset.type === "서버" || asset.type === "PC";
  if (
    asset.patch_status !== "적용완료" ||
    !asset.managed ||
    (needsEdrAv && (!asset.edr || !asset.av)) ||
    (asset.violation_ids ?? []).length > 0
  ) return "취약";
  return "정상";
}

const CATEGORY_TABS = [
  { id: "전체",       label: "전체" },
  { id: "hardware",   label: "Hardware" },
  { id: "software",   label: "Software" },
  { id: "credential", label: "Credential" },
  { id: "api",        label: "API" },
];



// ── 공통 컴포넌트 ─────────────────────────────────────────────────────────────

/* 차트 아래의 범례 디자인 정의 */
function LegendItem({ label, color, dash, isBar }) {
  return (
    <span style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: "#73726c" }}>
      {isBar ? (
        <span style={{ width: 12, height: 12, background: color + "33", border: `1px solid ${color}`, display: "inline-block", borderRadius: 2 }} />
      ) : (
        <svg width={20} height={10}>
          <line x1={0} y1={5} x2={20} y2={5} stroke={color} strokeWidth={2} strokeDasharray={dash || undefined} />
          {!dash && <circle cx={10} cy={5} r={3} fill={color} />}
        </svg>
      )}
      {label}
    </span>
  );
}

/* 각 섹션 제목 위의 라벨 정의 */
function SubLabel({ children }) {
  return <p style={{ fontSize: 11, fontWeight: 500, color: "#73726c", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 10, marginTop: 4 }}>{children}</p>;
}



// ── (전체) 카테고리 요약 카드 ─────────────────────────────────────────────────

// 3개 카테고리의 핵심 수치를 한눈에 보여주는 요약 카드
// 클릭하면 해당 카테고리 상세 탭으로 이동
function CategorySummaryCards({ assets, softwareAssets, credentialAssets, apiAssets, onCategoryClick }) {
  const now  = new Date();
  const soon = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000); // 90일 후

  const hwTotal  = assets.length;
  const hwOnline = assets.filter((a) => a.online_status === "온라인").length;
  const hwVuln   = assets.filter((a) => a.status === "취약" && a.managed).length;

  const swVuln      = softwareAssets.filter((s) => (s.cve_count > 0 && s.patch_status !== "적용완료") || s.eol || (s.violation_ids ?? []).length > 0).length;
  const swUnpatched = softwareAssets.filter((s) => s.patch_status !== "적용완료").length;
  const swEol       = softwareAssets.filter((s) => s.eol).length;

  const credExposed  = credentialAssets.filter((c) => c.exposed).length;
  const credExpiring = credentialAssets.filter((c) => c.expires_at && new Date(c.expires_at) <= soon).length;
  const credOverPriv = credentialAssets.filter((c) => c.privilege === "과다" || c.privilege === "최고").length;

  const apiExposed    = apiAssets.filter((a) => a.exposed).length;
  const apiNoAuth     = apiAssets.filter((a) => a.auth === "없음").length;
  const apiNoRateLimit = apiAssets.filter((a) => !a.rate_limit).length;

  const categories = [
    {
      id: "hardware",
      label: "Hardware",
      desc: "디바이스 · 서버 · 네트워크 장비",
      items: [
        { label: "총 디바이스",  value: hwTotal },
        { label: "온라인",       value: hwOnline },
        { label: "취약 디바이스", value: hwVuln, alert: hwVuln > 0 },
      ],
    },
    {
      id: "software",
      label: "Software",
      desc: "OS · 펌웨어 · 플랫폼 · 애플리케이션",
      items: [
        { label: "취약 소프트웨어", value: swVuln,      alert: swVuln > 0 },
        { label: "패치 미적용",     value: swUnpatched, alert: swUnpatched > 0 },
        { label: "EOL 버전",        value: swEol,       alert: swEol > 0 },
      ],
    },
    {
      id: "credential",
      label: "Credential",
      desc: "서명키 · 인증서 · 계정 · API 토큰",
      items: [
        { label: "노출된 키 / 계정", value: credExposed,  alert: credExposed > 0 },
        { label: "만료 임박 (90일)", value: credExpiring, alert: credExpiring > 0 },
        { label: "과도 권한",        value: credOverPriv, alert: credOverPriv > 0 },
      ],
    },
    {
      id: "api",
      label: "API",
      desc: "REST · GraphQL · gRPC · WebSocket",
      items: [
        { label: "외부 노출 API",       value: apiExposed,     alert: apiExposed > 0 },
        { label: "인증 없는 API",       value: apiNoAuth,      alert: apiNoAuth > 0 },
        { label: "Rate Limit 미적용",   value: apiNoRateLimit, alert: apiNoRateLimit > 0 },
      ],
    },
  ];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 16 }}>
      {categories.map((cat) => (
        <div
          key={cat.id}
          onClick={() => onCategoryClick(cat.id)}
          style={{ ...card, cursor: "pointer", transition: "box-shadow 0.15s" }}
          onMouseEnter={(e) => { e.currentTarget.style.boxShadow = "0 2px 12px rgba(24,95,165,0.12)"; }}
          onMouseLeave={(e) => { e.currentTarget.style.boxShadow = "none"; }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
            <div>
              <p style={{ fontSize: 13, fontWeight: 600, margin: "0 0 3px", color: "#1a1a18" }}>{cat.label}</p>
              <p style={{ fontSize: 10, color: "#73726c", margin: 0 }}>{cat.desc}</p>
            </div>
            <span style={{ fontSize: 11, color: "#185FA5", flexShrink: 0, marginLeft: 8 }}>상세 →</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
            {cat.items.map((item) => (
              <div key={item.label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 12, color: "#73726c" }}>{item.label}</span>
                <span style={{ fontSize: 18, fontWeight: 600, color: item.alert ? "#0C447C" : "#b0aea8" }}>
                  {item.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── (1) Hardware ─────────────────────────────────────────────────────────────

function InventoryCards({ assets }) {
  const total = assets.length;

  // 1) 고정 카테고리 정의
  const TYPE_ORDER = ["서버", "PC", "IoT", "네트워크 장비"];
  const SEGMENT_ORDER = ["DMZ", "내부망", "폐쇄망"];

  // 2) 유형별 집계: 목록에 없는 값은 "기타"로 처리
  const typeCounts = [
    ...TYPE_ORDER.map((type) => ({
      label: type,
      count: assets.filter((a) => a.type === type).length,
    })),
    {
      label: "기타",
      count: assets.filter((a) => !TYPE_ORDER.includes(a.type)).length,
    },
  ].filter((item) => item.count > 0 || item.label !== "기타");

  const maxType = Math.max(...typeCounts.map((x) => x.count), 1);

  // 3) 네트워크 구간별 집계: 목록에 없는 값은 "기타"로 처리
  const segCounts = [
    ...SEGMENT_ORDER.map((segment) => ({
      label: segment,
      count: assets.filter((a) => a.segment === segment).length,
      color: SEGMENT_COLOR[segment],
    })),
    {
      label: "기타",
      count: assets.filter((a) => !SEGMENT_ORDER.includes(a.segment)).length,
      color: "#73726c",
    },
  ].filter((item) => item.count > 0 || item.label !== "기타");

  const maxSeg = Math.max(...segCounts.map((x) => x.count), 1);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 12 }}>
      <div style={card}>
        <p style={cardTitle}>유형별 분포</p>

        {typeCounts.map(({ label, count }) => (
          <div key={label}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 3 }}>
              <span>{label}</span>
              <span>{count}대</span>
            </div>

            <div style={{ height: 5, background: "#f1efea", borderRadius: 99 }}>
              <div
                style={{
                  height: 5,
                  width: `${(count / maxType) * 100}%`,
                  background: "#185FA5",
                  borderRadius: 99,
                }}
              />
            </div>
          </div>
        ))}
      </div>

      <div style={card}>
        <p style={cardTitle}>네트워크 구간별</p>

        {segCounts.map(({ label, count, color }) => (
          <div key={label}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 3 }}>
              <span>{label}</span>
              <span style={{ color }}>{count}대</span>
            </div>

            <div style={{ height: 5, background: "#f1efea", borderRadius: 99 }}>
              <div
                style={{
                  height: 5,
                  width: `${(count / maxSeg) * 100}%`,
                  background: color,
                  borderRadius: 99,
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* 각 카테고리에서 공통으로 쓰는 KPI 카드 — kpis 배열을 그대로 렌더링 */
function SecurityKPI({ kpis }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: `repeat(${kpis.length}, 1fr)`, gap: 10, marginBottom: 12 }}>
      {kpis.map((k) => (
        <div key={k.label} style={{ ...card, padding: "14px 16px", marginBottom: 0 }}>
          <p style={{ fontSize: 11, color: "#73726c", margin: "0 0 6px" }}>{k.label}</p>
          <p style={{ fontSize: 26, fontWeight: 700, color: k.color, margin: "0 0 4px" }}>{k.value}</p>
          {k.sub    && <p style={{ fontSize: 10, color: "#b0b0b0", margin: "0 0 2px" }}>{k.sub}</p>}
          {k.detail && <p style={{ fontSize: 10, color: k.color, margin: 0, fontWeight: 500 }}>{k.detail}</p>}
        </div>
      ))}
    </div>
  );
}

/* 날짜별 추이 컴포넌트 */
function TrendCharts({ assetHistory }) {
  return (
    <>
      <SubLabel>날짜별 추이 — 핵심 지표</SubLabel>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
        <div style={card}>
          <p style={cardTitle}>① 취약 자산 수 변화 <span style={chartNote}>카테고리별 공격 표면 확대 여부</span></p>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={assetHistory} margin={{ top: 5, right: 16, bottom: 5, left: 0 }}>
              <CartesianGrid stroke="rgba(0,0,0,0.06)" />
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: "#73726c" }} />
              <YAxis tick={{ fontSize: 10, fill: "#73726c" }} />
              <Tooltip contentStyle={{ fontSize: 11, borderRadius: 6, border: "0.5px solid rgba(0,0,0,0.1)" }} formatter={(v, n) => [v + "개", n]} />
              <Line type="monotone" dataKey="vulnerable_hw"   name="하드웨어"  stroke="#0C447C" strokeWidth={2} dot={{ r: 3 }} />
              <Line type="monotone" dataKey="vulnerable_sw"   name="소프트웨어" stroke="#185FA5" strokeWidth={2} dot={{ r: 3 }} />
              <Line type="monotone" dataKey="vulnerable_cred" name="자격증명"  stroke="#378ADD" strokeWidth={2} dot={{ r: 3 }} strokeDasharray="5 3" />
              <Line type="monotone" dataKey="vulnerable_api"  name="API"       stroke="#85B7EB" strokeWidth={2} dot={{ r: 3 }} strokeDasharray="5 3" />
            </LineChart>
          </ResponsiveContainer>
          <div style={legendRow}>
            <LegendItem label="하드웨어"  color="#0C447C" />
            <LegendItem label="소프트웨어" color="#185FA5" />
            <LegendItem label="자격증명"  color="#378ADD" dash="5 3" />
            <LegendItem label="API"       color="#85B7EB" dash="5 3" />
          </div>
        </div>

        <div style={card}>
          <p style={cardTitle}>② 패치 적용률 추이 <span style={chartNote}>침해사고 주요 원인</span></p>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={assetHistory} margin={{ top: 5, right: 16, bottom: 5, left: 0 }}>
              <CartesianGrid stroke="rgba(0,0,0,0.06)" />
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: "#73726c" }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "#73726c" }} tickFormatter={(v) => `${v}%`} />
              <Tooltip contentStyle={{ fontSize: 11, borderRadius: 6, border: "0.5px solid rgba(0,0,0,0.1)" }} formatter={(v, n) => [v + "%", n]} />
              <Line type="monotone" dataKey="patch_pct_hw" name="하드웨어" stroke="#0C447C" strokeWidth={2} dot={{ r: 3 }} />
              <Line type="monotone" dataKey="patch_pct_sw" name="소프트웨어" stroke="#378ADD" strokeWidth={2} dot={{ r: 3 }} strokeDasharray="5 3" />
            </LineChart>
          </ResponsiveContainer>
          <div style={legendRow}>
            <LegendItem label="하드웨어"  color="#0C447C" />
            <LegendItem label="소프트웨어" color="#378ADD" dash="5 3" />
          </div>
        </div>
      </div>

      <div style={card}>
        <p style={cardTitle}>③ 신규 / 미등록(Shadow IT) 자산 추이 <span style={chartNote}>보안 사각지대 확인</span></p>
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={assetHistory} margin={{ top: 5, right: 20, bottom: 5, left: 0 }} barGap={4} barCategoryGap="35%">
            <CartesianGrid stroke="rgba(0,0,0,0.06)" />
            <XAxis dataKey="date" tick={{ fontSize: 10, fill: "#73726c" }} />
            <YAxis tick={{ fontSize: 10, fill: "#73726c" }} />
            <Tooltip contentStyle={{ fontSize: 11, borderRadius: 6, border: "0.5px solid rgba(0,0,0,0.1)" }} formatter={(v, n) => [v + "대", n]} />
            <Bar dataKey="new_assets"   name="신규 등록"  fill="#378ADD" fillOpacity={0.7} radius={[3, 3, 0, 0]} />
            <Bar dataKey="unregistered" name="미등록 자산" fill="#0C447C" fillOpacity={0.8} radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
        <div style={legendRow}>
          <LegendItem label="신규 등록"  color="#378ADD" isBar />
          <LegendItem label="미등록 자산" color="#0C447C" isBar />
        </div>
      </div>
    </>
  );
}

/* 자산 목록 테이블 컴포넌트 */
function AssetList({ assets }) {
  const [typeFilter,   setTypeFilter]   = useState("전체");
  const [statusFilter, setStatusFilter] = useState("전체");
  
  // 필터링된 자산 목록 계산 (유형과 상태 기준을 모두 만족 하는 자산을 필터링)
  const filtered = assets.filter((a) => {
    const typeOk   = typeFilter   === "전체" || a.type   === typeFilter;
    const statusOk = statusFilter === "전체" || a.status === statusFilter;
    return typeOk && statusOk;
  });

  return (
    <div style={card}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
        <p style={{ ...cardTitle, marginBottom: 0 }}>
          하드웨어 자산 목록
          <span style={{ fontSize: 11, fontWeight: 400, color: "#73726c", marginLeft: 6 }}>({filtered.length}건)</span>
        </p>
        <div style={{ display: "flex", gap: 15, flexWrap: "wrap" }}>
          <div style={{ display: "flex", gap: 4 }}>
            {TYPES.map((t) => (
              <button key={t} onClick={() => setTypeFilter(t)} style={filterBtn(typeFilter === t, "#185FA5")}>{t}</button>
            ))}
          </div>
          <div style={{ display: "flex", gap: 4 }}>
            {STATUSES.map((s) => (
              <button key={s} onClick={() => setStatusFilter(s)} style={filterBtn(statusFilter === s, "#0C447C")}>{s}</button>
            ))}
          </div>
        </div>
      </div>

      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, minWidth: 900 }}>
          <thead>
            <tr>
              {["자산 ID", "이름", "유형", "구간", "IP", "OS", "패치", "EDR", "AV", "관리 상태", "위반", "최근 확인"].map((h) => (
                <th key={h} style={th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={12} style={{ textAlign: "center", padding: "24px", color: "#b0b0b0", fontSize: 12 }}>
                  해당 조건의 자산이 없습니다
                </td>
              </tr>
            ) : filtered.map((a) => {
              const ss = STATUS_STYLE[a.status] || {};
              const ps = PATCH_STYLE[a.patch_status] || {};
              return (
                <tr key={a.id}>
                  <td style={td}><span style={{ fontWeight: 500, color: "#185FA5" }}>{a.id}</span></td>
                  <td style={{ ...td, fontWeight: 500 }}>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                      <span style={{ width: 6, height: 6, borderRadius: "50%", background: a.online_status === "온라인" ? "#1D9E75" : "#b0b0b0", flexShrink: 0 }} />
                      {a.name}
                    </span>
                  </td>
                  <td style={td}>
                    <span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{a.type}</span>
                  </td>
                  <td style={td}>
                    <span style={{ fontSize: 10, background: SEGMENT_COLOR[a.segment] + "20", color: SEGMENT_COLOR[a.segment], padding: "1px 6px", borderRadius: 99 }}>
                      {a.segment}
                    </span>
                  </td>
                  <td style={{ ...td, fontFamily: "monospace", fontSize: 11, color: "#444" }}>{a.ip}</td>
                  <td style={{ ...td, color: "#73726c", fontSize: 11 }}>{a.os}</td>
                  <td style={td}>
                    <span style={{ fontSize: 10, fontWeight: 500, background: ps.bg, color: ps.text, padding: "2px 6px", borderRadius: 99 }}>
                      {a.patch_status}
                    </span>
                  </td>
                  <td style={{ ...td, textAlign: "center" }}>{a.edr ? <span style={{ color: "#085041" }}>✓</span> : <span style={{ color: "#E57373", fontWeight: 700 }}>✗</span>}</td>
                  <td style={{ ...td, textAlign: "center" }}>{a.av  ? <span style={{ color: "#085041" }}>✓</span> : <span style={{ color: "#E57373", fontWeight: 700 }}>✗</span>}</td>
                  <td style={td}>
                    <span style={{ fontSize: 10, fontWeight: 500, background: ss.bg, color: ss.text, padding: "2px 6px", borderRadius: 99 }}>
                      {a.status}
                    </span>
                  </td>
                  <td style={{ ...td, textAlign: "center" }}>
                    {a.violation_ids.length > 0
                      ? <span style={{ fontWeight: 700, color: "#0C447C" }}>{a.violation_ids.length}</span>
                      : <span style={{ color: "#c0c0c0" }}>—</span>}
                  </td>
                  <td style={{ ...td, color: "#73726c", fontSize: 11 }}>
                    {new Date(a.last_seen).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── (2) Software ─────────────────────────────────────────────────────────────

function SoftwareSection({ softwareAssets }) {
  const vulnCount      = softwareAssets.filter((s) => (s.cve_count > 0 && s.patch_status !== "적용완료") || s.eol || (s.violation_ids ?? []).length > 0).length;
  const unpatchedCount = softwareAssets.filter((s) => s.patch_status !== "적용완료").length;
  const eolCount       = softwareAssets.filter((s) => s.eol).length;

  return (
    <div>
      <SecurityKPI kpis={[
        { label: "취약 소프트웨어", value: vulnCount,      color: "#0C447C", sub: "CVE 미패치 · EOL · 불변식 위반" },
        { label: "패치 미적용",     value: unpatchedCount, color: "#0C447C", sub: "지연 + 미적용 합산" },
        { label: "EOL 버전",        value: eolCount,       color: "#185FA5", sub: "공식 지원 종료" },
      ]} />

      {/* 소프트웨어 목록 테이블 */}
      <div style={card}>
        <p style={cardTitle}>소프트웨어 목록</p>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, minWidth: 800 }}>
            <thead>
              <tr>
                {["ID", "이름", "유형", "버전", "연결 자산", "CVE 수", "패치 상태", "EOL", "불변식 위반", "마지막 업데이트"].map((h) => (
                  <th key={h} style={th}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {softwareAssets.length === 0 ? (
                <tr>
                  <td colSpan={10} style={{ textAlign: "center", padding: "24px", color: "#b0b0b0", fontSize: 12 }}>
                    소프트웨어 자산이 없습니다
                  </td>
                </tr>
              ) : softwareAssets.map((s) => {
                const ps = PATCH_STYLE[s.patch_status] || {};
                return (
                  <tr key={s.id}>
                    <td style={td}><span style={{ fontWeight: 500, color: "#185FA5" }}>{s.id}</span></td>
                    <td style={{ ...td, fontWeight: 500 }}>{s.name}</td>
                    <td style={td}>
                      <span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{s.type}</span>
                    </td>
                    <td style={{ ...td, fontFamily: "monospace", fontSize: 11, color: "#444" }}>{s.version}</td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{s.linked_asset}</td>
                    <td style={{ ...td, fontWeight: 700, color: s.cve_count > 0 ? "#0C447C" : "#c0c0c0", textAlign: "center" }}>
                      {s.cve_count > 0 ? s.cve_count : "—"}
                    </td>
                    <td style={td}>
                      <span style={{ fontSize: 10, fontWeight: 500, background: ps.bg, color: ps.text, padding: "2px 6px", borderRadius: 99 }}>
                        {s.patch_status}
                      </span>
                    </td>
                    <td style={{ ...td, textAlign: "center" }}>
                      {s.eol
                        ? <span style={{ fontSize: 10, fontWeight: 700, background: "#E6F1FB", color: "#0C447C", padding: "2px 6px", borderRadius: 99 }}>EOL</span>
                        : <span style={{ color: "#c0c0c0" }}>—</span>}
                    </td>
                    <td style={{ ...td, fontFamily: "monospace", fontSize: 11, color: "#185FA5" }}>
                      {(s.violation_ids ?? []).length > 0
                        ? s.violation_ids.join(", ")
                        : <span style={{ color: "#c0c0c0", fontFamily: "inherit" }}>—</span>}
                    </td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{s.last_updated}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── (3) Credential ────────────────────────────────────────────────────────────

function CredentialSection({ credentialAssets }) {
  const now  = new Date();
  const soon = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);

  // 취약 자격증명: 보안 위험 조건 기반 계산 (만료임박 제외)
  // 보관 방식(파일시스템/환경변수)은 MFA 여부 관계없이 독립적 위험
  // MFA는 계정 탈취 위험 요소로 별도 판단 (privilege와 결합)
  const isVuln = (c) =>
    c.exposed ||
    c.storage === "파일시스템" ||
    c.storage === "환경변수" ||
    ((c.privilege === "최고" || c.privilege === "과다") && !c.mfa) ||
    (c.violation_ids ?? []).length > 0;

  const vulnCount      = credentialAssets.filter(isVuln).length;
  const exposedCount   = credentialAssets.filter((c) => c.exposed).length;
  const storageCount   = credentialAssets.filter((c) => c.storage === "파일시스템" || c.storage === "환경변수").length;
  const privMfaCount   = credentialAssets.filter((c) => (c.privilege === "최고" || c.privilege === "과다") && !c.mfa).length;
  const violationCount = credentialAssets.filter((c) => (c.violation_ids ?? []).length > 0).length;
  const expiringCount  = credentialAssets.filter((c) => c.expires_at && new Date(c.expires_at) <= soon).length;
  const overPrivCount  = credentialAssets.filter((c) => c.privilege === "과다" || c.privilege === "최고").length;
  const noMfaCount     = credentialAssets.filter((c) => !c.mfa).length;

  return (
    <div>
      <SecurityKPI kpis={[
        { label: "취약 자격증명",    value: vulnCount,     color: "#0C447C", sub: "외부 노출 · 불안전 보관 방식 · 과도 권한 + MFA 미적용 · 불변식 위반 연결" },
        { label: "노출된 키 / 계정", value: exposedCount,  color: "#0C447C", sub: "외부 노출 확인됨",              detail: "즉시 교체 필요" },
        { label: "만료 임박 (90일)", value: expiringCount, color: "#185FA5", sub: "인증서 · 토큰 갱신 필요",        detail: "서비스 중단 위험" },
        { label: "과도 권한",        value: overPrivCount, color: "#185FA5", sub: "최소 권한 원칙 위반",            detail: "최고 · 과다 권한 합산" },
        { label: "MFA 미적용",       value: noMfaCount,    color: "#378ADD", sub: "계정 탈취 시 즉시 침해 가능",     detail: "MFA 미설정 자격증명" },
      ]} />

      {/* 자격증명 목록 테이블 */}
      <div style={card}>
        <p style={cardTitle}>자격증명 목록</p>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, minWidth: 900 }}>
            <thead>
              <tr>
                {["ID", "이름", "유형", "담당", "보관 방식", "MFA", "마지막 갱신", "만료일", "권한", "노출", "상태"].map((h) => (
                  <th key={h} style={th}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {credentialAssets.length === 0 ? (
                <tr>
                  <td colSpan={11} style={{ textAlign: "center", padding: "24px", color: "#b0b0b0", fontSize: 12 }}>
                    자격증명 자산이 없습니다
                  </td>
                </tr>
              ) : credentialAssets.map((c) => {
                const ss  = CRED_STATUS_STYLE[c.status] || {};
                const stg = STORAGE_STYLE[c.storage]    || {};
                const isExpiringSoon = c.expires_at && new Date(c.expires_at) <= soon;
                return (
                  <tr key={c.id}>
                    <td style={td}><span style={{ fontWeight: 500, color: "#185FA5" }}>{c.id}</span></td>
                    <td style={{ ...td, fontWeight: 500 }}>{c.name}</td>
                    <td style={td}>
                      <span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{c.type}</span>
                    </td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{c.owner}</td>
                    <td style={td}>
                      {/* HSM이 가장 안전, 파일시스템이 가장 위험 */}
                      <span style={{ fontSize: 10, fontWeight: 500, background: stg.bg || "#f1efea", color: stg.text || "#73726c", padding: "2px 6px", borderRadius: 99 }}>
                        {c.storage}
                      </span>
                    </td>
                    <td style={{ ...td, textAlign: "center" }}>
                      {c.mfa ? <span style={{ color: "#085041" }}>✓</span> : <span style={{ color: "#E57373", fontWeight: 700 }}>✗</span>}
                    </td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{c.last_rotated}</td>
                    <td style={{ ...td, fontSize: 11, fontWeight: isExpiringSoon ? 600 : 400, color: isExpiringSoon ? "#0C447C" : "#73726c" }}>
                      {c.expires_at ?? "—"}
                    </td>
                    <td style={td}>
                      <span style={{
                        fontSize: 10, padding: "1px 6px", borderRadius: 99, fontWeight: 500,
                        background: c.privilege === "최고" ? "#E6F1FB" : c.privilege === "과다" ? "#EEF4FD" : "#E1F5EE",
                        color:      c.privilege === "최고" ? "#0C447C" : c.privilege === "과다" ? "#185FA5" : "#085041",
                      }}>
                        {c.privilege}
                      </span>
                    </td>
                    <td style={{ ...td, textAlign: "center" }}>
                      {c.exposed
                        ? <span style={{ fontSize: 10, fontWeight: 700, background: "#E6F1FB", color: "#0C447C", padding: "2px 6px", borderRadius: 99 }}>노출</span>
                        : <span style={{ color: "#c0c0c0" }}>—</span>}
                    </td>
                    <td style={td}>
                      <span style={{ fontSize: 10, fontWeight: 500, background: ss.bg, color: ss.text, padding: "2px 6px", borderRadius: 99 }}>
                        {c.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── (4) API ───────────────────────────────────────────────────────────────────

const SCOPE_STYLE = {
  외부:   { bg: "#E6F1FB", text: "#0C447C" },
  파트너: { bg: "#EEF4FD", text: "#185FA5" },
  내부:   { bg: "#f1efea", text: "#73726c" },
};

function ApiSection({ apiAssets }) {
  const isVulnApi = (a) =>
    a.auth === "없음" ||
    (a.exposed && !a.rate_limit) ||
    (a.exposed && a.auth === "API Key") ||
    (a.violation_ids ?? []).length > 0;

  const vulnCount        = apiAssets.filter(isVulnApi).length;
  const dangerCount      = apiAssets.filter((a) => a.status === "위험").length;
  const vulnOnlyCount    = apiAssets.filter((a) => a.status === "취약").length;
  const exposedCount     = apiAssets.filter((a) => a.exposed).length;
  const noAuthCount      = apiAssets.filter((a) => a.auth === "없음").length;
  const noRateLimitCount = apiAssets.filter((a) => !a.rate_limit).length;

  return (
    <div>
      <SecurityKPI kpis={[
        { label: "취약 API",          value: vulnCount,        color: "#0C447C", sub: "인증 없음 · 외부 노출 + Rate Limit 미적용 · 외부 노출 + API Key 인증 · 불변식 위반 연결" },
        { label: "외부 노출 API",     value: exposedCount,     color: "#0C447C", sub: "인터넷 직접 노출",   detail: "외부 접근 가능" },
        { label: "인증 없는 API",     value: noAuthCount,      color: "#185FA5", sub: "무인증 접근 가능",   detail: "즉각 침해 위험" },
        { label: "Rate Limit 미적용", value: noRateLimitCount, color: "#185FA5", sub: "DoS 공격 취약",      detail: "요청 제한 없음" },
      ]} />

      {/* API 목록 테이블 */}
      <div style={card}>
        <p style={cardTitle}>API 목록</p>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, minWidth: 900 }}>
            <thead>
              <tr>
                {["ID", "이름", "유형", "엔드포인트", "인증", "범위", "Rate Limit", "연결 자산", "감사일"].map((h) => (
                  <th key={h} style={th}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {apiAssets.length === 0 ? (
                <tr>
                  <td colSpan={9} style={{ textAlign: "center", padding: "24px", color: "#b0b0b0", fontSize: 12 }}>
                    API 자산이 없습니다
                  </td>
                </tr>
              ) : apiAssets.map((a) => {
                const sc = SCOPE_STYLE[a.scope] || {};
                return (
                  <tr key={a.id}>
                    <td style={td}><span style={{ fontWeight: 500, color: "#185FA5" }}>{a.id}</span></td>
                    <td style={{ ...td, fontWeight: 500 }}>{a.name}</td>
                    <td style={td}>
                      <span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{a.type}</span>
                    </td>
                    <td style={{ ...td, fontFamily: "monospace", fontSize: 11, color: "#73726c" }}>{a.endpoint}</td>
                    <td style={td}>
                      <span style={{
                        fontSize: 10, fontWeight: 500, padding: "2px 6px", borderRadius: 99,
                        background: a.auth === "없음" ? "#E6F1FB" : "#E1F5EE",
                        color:      a.auth === "없음" ? "#0C447C" : "#085041",
                      }}>
                        {a.auth}
                      </span>
                    </td>
                    <td style={td}>
                      <span style={{ fontSize: 10, background: sc.bg || "#f1efea", color: sc.text || "#73726c", padding: "2px 6px", borderRadius: 99 }}>
                        {a.scope}
                      </span>
                    </td>
                    <td style={{ ...td, textAlign: "center" }}>
                      {a.rate_limit
                        ? <span style={{ color: "#085041" }}>✓</span>
                        : <span style={{ color: "#E57373", fontWeight: 700 }}>✗</span>}
                    </td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{a.linked_asset ?? "—"}</td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{a.last_audited}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── (5) 공유 컴포넌트 (전체 탭에서 사용) ──────────────────────────────────────

function PolicyCards({ assetPolicies }) {
  return (
    <div style={card}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 14 }}>
        <p style={{ ...cardTitle, marginBottom: 0 }}>정책 위반 현황</p>
        <span style={{ fontSize: 11, color: "#73726c" }}>— 불변식 위반 직접 연계</span>
      </div>
      {assetPolicies.length === 0 ? (
        <div style={{ padding: "24px 0", textAlign: "center" }}>
          <p style={{ fontSize: 13, color: "#73726c", margin: "0 0 6px" }}>등록된 정책 위반이 없습니다</p>
          <p style={{ fontSize: 11, color: "#b0aea8", margin: 0 }}>스캔 후 불변식 위반과 연계된 정책이 위반되면 표시됩니다</p>
        </div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          {assetPolicies.map((pol) => {
            const ps = POL_SEV_STYLE[pol.severity] || POL_SEV_STYLE.Medium;
            return (
              <div key={pol.id} style={{ border: `0.5px solid ${ps.border}`, borderRadius: 8, padding: "12px 14px", background: ps.bg }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
                  <div>
                    <span style={{ fontSize: 10, color: "#73726c" }}>{pol.id} · {pol.category}</span>
                    <p style={{ fontSize: 12, fontWeight: 600, color: ps.text, margin: "3px 0 0" }}>{pol.policy}</p>
                  </div>
                  <span style={{ fontSize: 10, fontWeight: 600, background: "#fff", color: ps.text, padding: "2px 8px", borderRadius: 99, flexShrink: 0, marginLeft: 8 }}>
                    {pol.severity}
                  </span>
                </div>
                <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: pol.linked_violations.length > 0 ? 6 : 0 }}>
                  <span style={{ fontSize: 12, color: ps.text, fontWeight: 700 }}>위반 자산 {pol.violating_assets.length}대</span>
                  <span style={{ fontSize: 10, color: "#73726c" }}>
                    — {pol.violating_assets.slice(0, 2).join(", ")}{pol.violating_assets.length > 2 ? ` 외 ${pol.violating_assets.length - 2}건` : ""}
                  </span>
                </div>
                {pol.linked_violations.length > 0 && (
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {pol.linked_violations.map((v) => (
                      <span key={v} style={{ fontSize: 10, background: "rgba(255,255,255,0.7)", color: ps.text, padding: "1px 6px", borderRadius: 4, border: `0.5px solid ${ps.border}` }}>
                        {v}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* 이벤트 피드 컴포넌트 */
function EventFeed({ assetEvents }) {
  const [showAll, setShowAll] = useState(false);
  const visible = showAll ? assetEvents : assetEvents.slice(0, 5);

  return (
    <div style={card}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 14 }}>
        <p style={{ ...cardTitle, marginBottom: 0 }}>탐지 이벤트</p>
        <span style={{ fontSize: 11, color: "#73726c" }}>— NAC / SIEM 통합 피드</span>
        <span style={{ marginLeft: "auto", fontSize: 11, color: "#73726c" }}>{assetEvents.length}건</span>
      </div>
      {/* 이벤트가 없을 때 빈 상태 메시지 */}
      {assetEvents.length === 0 ? (
        <div style={{ padding: "24px 0", textAlign: "center" }}>
          <p style={{ fontSize: 13, color: "#73726c", margin: "0 0 6px" }}>탐지된 이벤트가 없습니다</p>
          <p style={{ fontSize: 11, color: "#b0aea8", margin: 0 }}>NAC / SIEM에서 이벤트가 수집되면 여기에 표시됩니다</p>
        </div>
      ) : (
        <>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            {visible.map((evt) => {
              const ts = EVT_TYPE_STYLE[evt.type] || {};
              const ss = SEV_STYLE[evt.severity]  || {};
              return (
                <div key={evt.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 10px", border: "0.5px solid rgba(0,0,0,0.07)", borderRadius: 7, background: "#fafbfc" }}>
                  <span style={{ fontSize: 9, fontWeight: 600, background: ts.bg, color: ts.text, padding: "2px 7px", borderRadius: 99, flexShrink: 0 }}>
                    {evt.type}
                  </span>
                  <span style={{ fontSize: 12, color: "#1a1a18", flex: 1 }}>{evt.desc}</span>
                  <span style={{ fontSize: 10, color: "#73726c", flexShrink: 0 }}>{evt.zone}</span>
                  <span style={{ fontSize: 9, fontWeight: 600, background: ss.bg, color: ss.text, padding: "2px 7px", borderRadius: 99, flexShrink: 0 }}>
                    {evt.severity}
                  </span>
                  <span style={{ fontSize: 10, color: "#b0b0b0", flexShrink: 0 }}>
                    {new Date(evt.time).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
                  </span>
                </div>
              );
            })}
          </div>
          {assetEvents.length > 5 && (
            <button
              onClick={() => setShowAll((v) => !v)}
              style={{ marginTop: 10, background: "none", border: "0.5px solid rgba(0,0,0,0.12)", borderRadius: 6, cursor: "pointer", fontSize: 11, color: "#73726c", padding: "4px 12px" }}
            >
              {showAll ? "접기 ▲" : `더 보기 (${assetEvents.length - 5}건) ▼`}
            </button>
          )}
        </>
      )}
    </div>
  );
}

function AssetOverviewTable({ assets, softwareAssets, credentialAssets, apiAssets }) {
  const CATEGORY_STYLE = {
    Hardware:   { bg: "#E6F1FB", text: "#0C447C" },
    Software:   { bg: "#F0F6FE", text: "#378ADD" },
    Credential: { bg: "#FFF8E1", text: "#8B6914" },
    API:        { bg: "#E1F5EE", text: "#085041" },
  };

  const STATUS_ALL = {
    위험:    { bg: "#E6F1FB", text: "#0C447C" },
    취약:    { bg: "#EEF4FD", text: "#185FA5" },
    만료임박: { bg: "#FFF8E1", text: "#8B6914" },
    정상:    { bg: "#E1F5EE", text: "#085041" },
  };

  const rows = [
    ...assets.map((a) => ({
      category: "Hardware",
      id: a.id, name: a.name, subType: a.type,
      patchStatus: a.patch_status,
      violationCount: a.violation_ids.length,
      status: a.status,
      onlineStatus: a.online_status,
    })),
    ...(softwareAssets ?? []).map((s) => ({
      category: "Software",
      id: s.id, name: s.name, subType: s.type,
      patchStatus: s.patch_status,
      violationCount: (s.violation_ids ?? []).length,
      status: ((s.cve_count > 0 && s.patch_status !== "적용완료") || s.eol || (s.violation_ids ?? []).length > 0) ? "취약" : "정상",
      onlineStatus: null,
    })),
    ...(credentialAssets ?? []).map((c) => ({
      category: "Credential",
      id: c.id, name: c.name, subType: c.type,
      patchStatus: null,
      violationCount: (c.violation_ids ?? []).length,
      status: c.status,
      onlineStatus: null,
    })),
    ...(apiAssets ?? []).map((a) => ({
      category: "API",
      id: a.id, name: a.name, subType: a.type,
      patchStatus: null,
      violationCount: (a.violation_ids ?? []).length,
      status: a.status,
      onlineStatus: null,
    })),
  ];

  return (
    <div style={card}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <p style={{ ...cardTitle, marginBottom: 0 }}>전체 자산 목록</p>
        <span style={{ fontSize: 11, color: "#73726c" }}>{rows.length}개</span>
      </div>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr>
              {["카테고리", "ID", "이름", "유형", "패치 상태", "불변식 위반", "상태"].map((h) => (
                <th key={h} style={th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const cs = CATEGORY_STYLE[row.category] || {};
              const ps = PATCH_STYLE[row.patchStatus] || {};
              const ss = STATUS_ALL[row.status] || {};
              return (
                <tr key={row.id}>
                  <td style={td}>
                    <span style={{ fontSize: 10, fontWeight: 500, background: cs.bg, color: cs.text, padding: "1px 7px", borderRadius: 99 }}>{row.category}</span>
                  </td>
                  <td style={{ ...td, fontFamily: "monospace", fontSize: 11, color: "#185FA5" }}>{row.id}</td>
                  <td style={{ ...td, fontWeight: 500 }}>
                    {row.onlineStatus !== null ? (
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                        <span style={{ width: 6, height: 6, borderRadius: "50%", background: row.onlineStatus === "온라인" ? "#1D9E75" : "#b0b0b0", flexShrink: 0 }} />
                        {row.name}
                      </span>
                    ) : row.name}
                  </td>
                  <td style={td}>
                    <span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{row.subType}</span>
                  </td>
                  <td style={td}>
                    {row.patchStatus
                      ? <span style={{ fontSize: 10, fontWeight: 500, background: ps.bg, color: ps.text, padding: "2px 6px", borderRadius: 99 }}>{row.patchStatus}</span>
                      : <span style={{ color: "#c0c0c0" }}>—</span>}
                  </td>
                  <td style={{ ...td, textAlign: "center" }}>
                    {row.violationCount > 0
                      ? <span style={{ fontWeight: 700, color: "#0C447C" }}>{row.violationCount}</span>
                      : <span style={{ color: "#c0c0c0" }}>—</span>}
                  </td>
                  <td style={td}>
                    <span style={{ fontSize: 10, fontWeight: 500, background: ss.bg, color: ss.text, padding: "2px 6px", borderRadius: 99 }}>{row.status}</span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── 메인 컴포넌트 ─────────────────────────────────────────────────────────────

export default function AssetSection({ assets, assetHistory, assetEvents, assetPolicies, softwareAssets, credentialAssets, apiAssets }) {
  const [activeCategory, setActiveCategory] = useState("전체");

  // API 연동 전 또는 데이터가 아직 없을 때 null/undefined 방어 — 각 하위 컴포넌트에 빈 배열로 전달
  const safeAssets     = assets           ?? [];
  const enrichedAssets = safeAssets.map((a) => ({ ...a, status: deriveAssetStatus(a) }));
  const safeHistory    = assetHistory     ?? [];
  const safeEvents     = assetEvents      ?? [];
  const safePolicies   = assetPolicies    ?? [];
  const safeSoftware   = softwareAssets   ?? [];
  const safeCredential = credentialAssets ?? [];
  const safeApi        = apiAssets        ?? [];

  return (
    <div>
      {/* 카테고리 탭 */}
      <div style={{ display: "flex", gap: 6, marginBottom: 24 }}>
        {CATEGORY_TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveCategory(tab.id)}
            style={{
              padding: "5px 14px", borderRadius: 99, border: "0.5px solid",
              fontSize: 12, cursor: "pointer",
              borderColor: activeCategory === tab.id ? "#185FA5" : "rgba(0,0,0,0.12)",
              background:  activeCategory === tab.id ? "#185FA5" : "transparent",
              color:       activeCategory === tab.id ? "#fff"    : "#73726c",
              fontWeight:  activeCategory === tab.id ? 500       : 400,
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* 전체 탭: 카테고리 요약 + 추이 차트 + 전체 자산 목록 */}
      {activeCategory === "전체" && (
        <>
          <SubLabel>카테고리별 현황</SubLabel>
          <CategorySummaryCards
            assets={enrichedAssets}
            softwareAssets={safeSoftware}
            credentialAssets={safeCredential}
            apiAssets={safeApi}
            onCategoryClick={setActiveCategory}
          />
          <TrendCharts assetHistory={safeHistory} />
          <SubLabel>전체 자산</SubLabel>
          <AssetOverviewTable
            assets={enrichedAssets}
            softwareAssets={safeSoftware}
            credentialAssets={safeCredential}
            apiAssets={safeApi}
          />
          {/* <SubLabel>탐지 이벤트</SubLabel>
          <EventFeed assetEvents={safeEvents} /> */}
        </>
      )}

      {/* Hardware 탭: 디바이스 인벤토리 상세 */}
      {activeCategory === "hardware" && (
        <>
          <SubLabel>자산 인벤토리</SubLabel>
          <InventoryCards assets={enrichedAssets} />
          <SubLabel>보안 상태 KPI</SubLabel>
          <SecurityKPI kpis={[
            { label: "취약 자산",        color: "#0C447C", sub: "패치 미완료 · EDR/백신 미설치 · 불변식 위반 (관리 자산 기준)", detail: "서버·PC만 에이전트 적용",                                                                                                                                    value: enrichedAssets.filter((a) => a.managed && a.status === "취약").length },
            { label: "패치 미적용",      color: "#0C447C", sub: "지연 + 미적용 합산 (관리 자산 기준)",  detail: `지연 ${enrichedAssets.filter((a) => a.managed && a.patch_status === "지연").length} / 미적용 ${enrichedAssets.filter((a) => a.managed && a.patch_status === "미적용").length}`, value: enrichedAssets.filter((a) => a.managed && a.patch_status !== "적용완료").length },
            { label: "불변식 위반 보유", color: "#0C447C", sub: "violation 연결 자산 (관리 자산 기준)",  detail: `총 위반 ${enrichedAssets.filter((a) => a.managed).reduce((s, a) => s + a.violation_ids.length, 0)}건`,                                                                     value: enrichedAssets.filter((a) => a.managed && a.violation_ids.length > 0).length },
            { label: "EDR 미설치",       color: "#185FA5", sub: "초기 침투 진입점 위험 (관리 자산 기준)", detail: "서버 · PC 대상",                                                                                                                                                          value: enrichedAssets.filter((a) => a.managed && !a.edr && (a.type === "서버" || a.type === "PC")).length },
            { label: "백신 미설치",      color: "#185FA5", sub: "악성코드 무방비 (관리 자산 기준)",       detail: "서버 · PC 대상",                                                                                                                                                          value: enrichedAssets.filter((a) => a.managed && !a.av  && (a.type === "서버" || a.type === "PC")).length },
          ]} />
          <SubLabel> 하드웨어 자산 목록</SubLabel>
          <AssetList assets={enrichedAssets} />
        </>
      )}

      {/* Software 탭: OS · 펌웨어 · 애플리케이션 */}
      {activeCategory === "software" && (
        <SoftwareSection softwareAssets={safeSoftware} />
      )}

      {/* Credential 탭: 서명키 · 인증서 · 계정 · API 토큰 */}
      {activeCategory === "credential" && (
        <CredentialSection credentialAssets={safeCredential} />
      )}

      {/* API 탭: REST · GraphQL · gRPC · WebSocket */}
      {activeCategory === "api" && (
        <ApiSection apiAssets={safeApi} />
      )}
    </div>
  );
}

// ── 스타일 상수 ───────────────────────────────────────────────────────────────

const filterBtn = (active, activeColor) => ({
  padding: "3px 10px", borderRadius: 99, fontSize: 11, cursor: "pointer", border: "0.5px solid",
  borderColor: active ? activeColor : "rgba(0,0,0,0.12)",
  background:  active ? activeColor : "transparent",
  color:       active ? "#fff"      : "#73726c",
  fontWeight:  active ? 500 : 400,
});

const legendRow = { display: "flex", gap: 14, justifyContent: "center", marginTop: 6 };
const card      = { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: 16, marginBottom: 12 };
const cardTitle = { fontSize: 13, fontWeight: 500, marginBottom: 14 };
const chartNote = { fontSize: 10, fontWeight: 400, color: "#73726c", marginLeft: 6 };
const th = { textAlign: "left", color: "#73726c", fontWeight: 400, padding: "6px 8px", borderBottom: "0.5px solid rgba(0,0,0,0.1)" };
const td = { padding: "7px 8px", borderBottom: "0.5px solid rgba(0,0,0,0.08)", color: "#1a1a18" };
