import { useState } from "react";
import {
  LineChart, Line, BarChart, Bar,
  XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer,
} from "recharts";

// ── 상수 ─────────────────────────────────────────────────────────────────────

const STATUS_STYLE = {
  취약: { bg: "#EEF4FD", text: "#185FA5" },
  정상: { bg: "#E1F5EE", text: "#085041" },
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

const CRED_STATUS_STYLE = {
  위험:    { bg: "#E6F1FB", text: "#0C447C" },
  취약:    { bg: "#EEF4FD", text: "#185FA5" },
  만료임박: { bg: "#FFF8E1", text: "#8B6914" },
  정상:    { bg: "#E1F5EE", text: "#085041" },
};

const STORAGE_STYLE = {
  HSM:      { bg: "#E1F5EE", text: "#085041" },
  파일시스템: { bg: "#E6F1FB", text: "#0C447C" },
  환경변수:  { bg: "#EEF4FD", text: "#185FA5" },
  DB:       { bg: "#F0F6FE", text: "#378ADD" },
  "-":      { bg: "#f1efea", text: "#73726c" },
};

const OBS_STATUS_STYLE = {
  registered:                    { bg: "#E1F5EE", text: "#085041", label: "등록됨" },
  unregistered_asset_candidate:  { bg: "#EEF4FD", text: "#185FA5", label: "미등록 후보" },
  expected_and_observed:         { bg: "#E1F5EE", text: "#085041", label: "예상+관찰" },
  expected:                      { bg: "#F0F6FE", text: "#378ADD", label: "예상" },
  observed:                      { bg: "#FFF8E1", text: "#8B6914", label: "관찰됨" },
  unregistered_service_candidate:{ bg: "#EEF4FD", text: "#185FA5", label: "미등록 서비스" },
};

const EVT_CAT_STYLE = {
  attack_execution:  { bg: "#E6F1FB", text: "#0C447C", label: "공격 실행" },
  environment_state: { bg: "#f1efea", text: "#73726c", label: "환경 상태" },
};

const SEGMENT_COLOR = { DMZ: "#185FA5", 내부망: "#378ADD", 폐쇄망: "#85B7EB" };
const PATCH_STYLE   = {
  "적용완료": { bg: "#E1F5EE", text: "#085041" },
  "미적용":   { bg: "#EEF4FD", text: "#185FA5" },
  "지연":     { bg: "#FFF8E1", text: "#8B6914" },
};
const TYPES         = ["전체", "서버", "PC", "IoT", "네트워크 장비"];
const STATUSES      = ["전체", "취약", "정상"];

const CATEGORY_TABS = [
  { id: "전체",       label: "전체" },
  { id: "hardware",   label: "Hardware" },
  // [비활성] software_assets 테이블 미구현
  // { id: "software", label: "Software" },
  { id: "credential", label: "Credential" },  // evidence_events 기반
  { id: "api",        label: "API" },          // evidence_events 기반
  { id: "service",    label: "서비스" },
  { id: "evidence",   label: "Evidence" },
];

// ── 헬퍼 ─────────────────────────────────────────────────────────────────────

function assetId(a)            { return a.asset_id  || a.id; }
function assetName(a)          { return a.asset_name || a.name; }
function assetType(a)          { return a.asset_type || a.type; }
function assetIp(a)            { return a.ip_hint    || a.ip; }
function assetViolations(a)    { return a.related_invariant_ids || a.violation_ids || []; }
function assetObsStatus(a)     { return a.observation_status || (a.managed ? "registered" : "unregistered_asset_candidate"); }

function deriveAssetStatus(asset) {
  if (assetViolations(asset).length > 0) return "취약";
  return "정상";
}

// ── 공통 컴포넌트 ─────────────────────────────────────────────────────────────

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

function SubLabel({ children }) {
  return <p style={{ fontSize: 11, fontWeight: 500, color: "#73726c", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 10, marginTop: 4 }}>{children}</p>;
}

// ── (전체) 카테고리 요약 카드 ─────────────────────────────────────────────────

function CategorySummaryCards({ assets, services, onCategoryClick }) {
  const hwTotal  = assets.length;
  const hwVuln   = assets.filter((a) => assetViolations(a).length > 0).length;

  const svcUnreg = services.filter((s) => s.observation_status === "unregistered_service_candidate").length;

  const categories = [
    {
      id: "hardware",
      label: "Hardware",
      desc: "디바이스 · 서버 · 네트워크 장비",
      items: [
        { label: "총 자산",       value: hwTotal },
        { label: "불변식 위반",   value: hwVuln, alert: hwVuln > 0 },
      ],
    },
    // [비활성] software_assets / credential_assets / api_assets 테이블 미구현
    // {
    //   id: "software", label: "Software", desc: "OS · 펌웨어 · 플랫폼 · 애플리케이션",
    //   items: [ ... ],
    // },
    // {
    //   id: "credential", label: "Credential", desc: "서명키 · 인증서 · 계정 · API 토큰",
    //   items: [ ... ],
    // },
    // {
    //   id: "api", label: "API", desc: "REST · GraphQL · gRPC · WebSocket",
    //   items: [ ... ],
    // },
    {
      id: "service",
      label: "서비스",
      desc: "서버 내 실행 중인 서비스",
      items: [
        { label: "총 서비스",     value: services.length },
        { label: "미등록 서비스", value: svcUnreg, alert: svcUnreg > 0 },
        { label: "Wazuh 수집",    value: services.filter((s) => s.collected_by_wazuh).length },
      ],
    },
  ];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12, marginBottom: 16 }}>
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

  const TYPE_ORDER    = ["서버", "PC", "IoT", "네트워크 장비"];
  const SEGMENT_ORDER = ["DMZ", "내부망", "폐쇄망"];

  const typeCounts = [
    ...TYPE_ORDER.map((type) => ({
      label: type,
      count: assets.filter((a) => assetType(a) === type).length,
    })),
    { label: "기타", count: assets.filter((a) => !TYPE_ORDER.includes(assetType(a))).length },
  ].filter((item) => item.count > 0 || item.label !== "기타");

  const maxType = Math.max(...typeCounts.map((x) => x.count), 1);

  const segCounts = [
    ...SEGMENT_ORDER.map((segment) => ({
      label: segment,
      count: assets.filter((a) => a.segment === segment).length,
      color: SEGMENT_COLOR[segment],
    })),
    { label: "기타", count: assets.filter((a) => !SEGMENT_ORDER.includes(a.segment)).length, color: "#73726c" },
  ].filter((item) => item.count > 0 || item.label !== "기타");

  const maxSeg = Math.max(...segCounts.map((x) => x.count), 1);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 12 }}>
      <div style={card}>
        <p style={cardTitle}>유형별 분포</p>
        {typeCounts.map(({ label, count }) => (
          <div key={label}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 3 }}>
              <span>{label}</span><span>{count}대</span>
            </div>
            <div style={{ height: 5, background: "#f1efea", borderRadius: 99 }}>
              <div style={{ height: 5, width: `${(count / maxType) * 100}%`, background: "#185FA5", borderRadius: 99 }} />
            </div>
          </div>
        ))}
      </div>
      <div style={card}>
        <p style={cardTitle}>네트워크 구간별</p>
        {segCounts.map(({ label, count, color }) => (
          <div key={label}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 3 }}>
              <span>{label}</span><span style={{ color }}>{count}대</span>
            </div>
            <div style={{ height: 5, background: "#f1efea", borderRadius: 99 }}>
              <div style={{ height: 5, width: `${(count / maxSeg) * 100}%`, background: color, borderRadius: 99 }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

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

function TrendCharts({ assetHistory }) {
  if (!assetHistory?.length) return null;
  return (
    <>
      <SubLabel>스캔별 추이 — 핵심 지표 (scan_asset_snapshot 기반)</SubLabel>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
        <div style={card}>
          <p style={cardTitle}>① 불변식 위반 자산 수 변화 <span style={chartNote}>violation 연결 자산 기준</span></p>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={assetHistory} margin={{ top: 5, right: 16, bottom: 5, left: 0 }}>
              <CartesianGrid stroke="rgba(0,0,0,0.06)" />
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: "#73726c" }} />
              <YAxis tick={{ fontSize: 10, fill: "#73726c" }} />
              <Tooltip contentStyle={{ fontSize: 11, borderRadius: 6, border: "0.5px solid rgba(0,0,0,0.1)" }} formatter={(v, n) => [v + "개", n]} />
              <Line type="monotone" dataKey="with_violation" name="불변식 위반 자산" stroke="#0C447C" strokeWidth={2} dot={{ r: 3 }} />
              <Line type="monotone" dataKey="total"          name="전체 자산"         stroke="#85B7EB" strokeWidth={1} dot={{ r: 2 }} strokeDasharray="3 3" />
            </LineChart>
          </ResponsiveContainer>
          <div style={legendRow}>
            <LegendItem label="불변식 위반 자산" color="#0C447C" />
            <LegendItem label="전체 자산"         color="#85B7EB" dash="3 3" />
          </div>
        </div>
      </div>
      <div style={card}>
        <p style={cardTitle}>③ 미등록(Shadow IT) / 신규 자산 추이 <span style={chartNote}>보안 사각지대 — scan_asset_snapshot.unregistered, scans.asset_count 차이</span></p>
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={assetHistory} margin={{ top: 5, right: 20, bottom: 5, left: 0 }} barGap={4} barCategoryGap="35%">
            <CartesianGrid stroke="rgba(0,0,0,0.06)" />
            <XAxis dataKey="date" tick={{ fontSize: 10, fill: "#73726c" }} />
            <YAxis tick={{ fontSize: 10, fill: "#73726c" }} />
            <Tooltip contentStyle={{ fontSize: 11, borderRadius: 6, border: "0.5px solid rgba(0,0,0,0.1)" }} formatter={(v, n) => [v + "대", n]} />
            <Bar dataKey="unregistered" name="미등록 자산" fill="#0C447C" fillOpacity={0.8} radius={[3, 3, 0, 0]} />
            <Bar dataKey="new_assets"   name="신규 등록"   fill="#378ADD" fillOpacity={0.7} radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
        <div style={legendRow}>
          <LegendItem label="미등록 자산" color="#0C447C" isBar />
          <LegendItem label="신규 등록"   color="#378ADD" isBar />
        </div>
      </div>
    </>
  );
}

// evidence_events를 자산 ID 기준으로 집계 (자산 목록 보완용)
function buildEvidenceStatsByAsset(evidenceEvents) {
  const stats = {};
  for (const e of (evidenceEvents ?? [])) {
    const aid = e.producer?.asset_id;
    if (!aid) continue;
    if (!stats[aid]) stats[aid] = { total: 0, attack: 0, lastTimestamp: null };
    stats[aid].total++;
    if (e.event_category === "attack_execution") stats[aid].attack++;
    if (!stats[aid].lastTimestamp || e.timestamp > stats[aid].lastTimestamp)
      stats[aid].lastTimestamp = e.timestamp;
  }
  return stats;
}

function AssetList({ assets, evidenceEvents }) {
  const [typeFilter,   setTypeFilter]   = useState("전체");
  const [statusFilter, setStatusFilter] = useState("전체");

  // evidence_events.producer_asset_id 기준 집계 — assets 테이블 데이터 보완
  const evStats = buildEvidenceStatsByAsset(evidenceEvents);

  const filtered = assets.filter((a) => {
    const typeOk   = typeFilter   === "전체" || assetType(a) === typeFilter;
    const statusOk = statusFilter === "전체" || a.status     === statusFilter;
    return typeOk && statusOk;
  });

  return (
    <div style={card}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
        <p style={{ ...cardTitle, marginBottom: 0 }}>
          하드웨어 자산 목록
          <span style={{ fontSize: 11, fontWeight: 400, color: "#73726c", marginLeft: 6 }}>({filtered.length}건)</span>
          <span style={{ fontSize: 10, fontWeight: 400, color: "#b0aea8", marginLeft: 8 }}>Evidence 컬럼: evidence_events.producer_asset_id 집계</span>
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
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, minWidth: 1080 }}>
          <thead>
            <tr>
              {["자산 ID", "이름", "유형", "Zone", "IP", "관측 상태", "불변식 위반", "Evidence", "공격 이벤트", "최근 확인"].map((h) => (
                <th key={h} style={th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={10} style={{ textAlign: "center", padding: "24px", color: "#b0b0b0", fontSize: 12 }}>
                  해당 조건의 자산이 없습니다
                </td>
              </tr>
            ) : filtered.map((a) => {
              const obs = OBS_STATUS_STYLE[assetObsStatus(a)] || {};
              const ev  = evStats[assetId(a)];
              // last_seen: evidence_events 기준 최신 타임스탬프 우선, 없으면 assets.last_seen
              const displayLastSeen = ev?.lastTimestamp ?? a.last_seen;
              return (
                <tr key={assetId(a)}>
                  <td style={td}><span style={{ fontWeight: 500, color: "#185FA5" }}>{assetId(a)}</span></td>
                  <td style={{ ...td, fontWeight: 500 }}>{assetName(a)}</td>
                  <td style={td}>
                    <span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{assetType(a)}</span>
                  </td>
                  <td style={td}>
                    <span style={{ fontSize: 10, background: (SEGMENT_COLOR[a.segment] || "#73726c") + "20", color: SEGMENT_COLOR[a.segment] || "#73726c", padding: "1px 6px", borderRadius: 99 }}>
                      {a.zone || a.segment || "-"}
                    </span>
                  </td>
                  <td style={{ ...td, fontFamily: "monospace", fontSize: 11, color: "#444" }}>{assetIp(a) || "-"}</td>
                  <td style={td}>
                    <span style={{ fontSize: 10, fontWeight: 500, background: obs.bg, color: obs.text, padding: "2px 6px", borderRadius: 99 }}>
                      {obs.label || assetObsStatus(a)}
                    </span>
                  </td>
                  <td style={{ ...td, textAlign: "center" }}>
                    {assetViolations(a).length > 0
                      ? <span style={{ fontWeight: 700, color: "#0C447C" }}>{assetViolations(a).length}</span>
                      : <span style={{ color: "#c0c0c0" }}>—</span>}
                  </td>
                  <td style={{ ...td, textAlign: "center" }}>
                    {ev
                      ? <span style={{ fontWeight: 500, color: "#185FA5" }}>{ev.total}</span>
                      : <span style={{ color: "#c0c0c0" }}>—</span>}
                  </td>
                  <td style={{ ...td, textAlign: "center" }}>
                    {ev?.attack > 0
                      ? <span style={{ fontWeight: 700, color: "#0C447C" }}>{ev.attack}</span>
                      : <span style={{ color: "#c0c0c0" }}>—</span>}
                  </td>
                  <td style={{ ...td, color: "#73726c", fontSize: 11 }}>
                    {displayLastSeen
                      ? new Date(displayLastSeen).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })
                      : "—"}
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

// ── (2-a) Credential — evidence_events 기반 (key_management_state, token_policy_state, account_state_event) ──

const BOOL_CELL = (v) => {
  if (v === null || v === undefined) return <span style={{ color: "#c0c0c0" }}>—</span>;
  return v
    ? <span style={{ color: "#085041" }}>✓</span>
    : <span style={{ fontWeight: 700, color: "#E57373" }}>✗</span>;
};

function CredentialFromEvidence({ evidenceEvents }) {
  const keyEvents     = evidenceEvents.filter((e) => e.evidence_type === "key_management_state");
  const tokenEvents   = evidenceEvents.filter((e) => e.evidence_type === "token_policy_state");
  const accountEvents = evidenceEvents.filter((e) =>
    e.evidence_type === "account_state_event" || e.evidence_type === "privileged_access_state"
  );

  const unapprovedStorage = keyEvents.filter((e) => e.observed?.approved_storage === false).length;
  const notRotated        = keyEvents.filter((e) => e.observed?.key_rotation_completed === false).length;
  const missingJtiCheck   = tokenEvents.filter((e) => e.observed?.validate_jti_registry === false).length;
  const missingRevCheck   = tokenEvents.filter((e) => e.observed?.validate_revocation === false).length;

  return (
    <div>
      <SecurityKPI kpis={[
        { label: "비승인 저장소 키",   value: unapprovedStorage, color: "#0C447C", sub: "key_management_state.observed.approved_storage = false" },
        { label: "미회전 키",           value: notRotated,        color: "#0C447C", sub: "key_rotation_completed = false" },
        { label: "JTI 검증 누락",       value: missingJtiCheck,   color: "#185FA5", sub: "token_policy_state.validate_jti_registry = false" },
        { label: "Revocation 검증 누락", value: missingRevCheck,  color: "#185FA5", sub: "token_policy_state.validate_revocation = false" },
        { label: "계정 이벤트",          value: accountEvents.length, color: "#378ADD", sub: "account_state_event / privileged_access_state" },
      ]} />

      {/* 키 관리 상태 */}
      {keyEvents.length > 0 && (
        <div style={card}>
          <p style={cardTitle}>키 관리 상태
            <span style={{ fontSize: 11, fontWeight: 400, color: "#73726c", marginLeft: 8 }}>evidence_type: key_management_state</span>
          </p>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, minWidth: 900 }}>
              <thead>
                <tr>
                  {["타임스탬프", "자산 ID", "key_id", "key_type", "key_status", "승인 저장소", "회전 완료", "마지막 회전"].map((h) => (
                    <th key={h} style={th}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {keyEvents.map((e) => {
                  const o = e.observed ?? {};
                  return (
                    <tr key={e.evidence_id}>
                      <td style={{ ...td, fontSize: 11, color: "#73726c" }}>
                        {new Date(e.timestamp).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
                      </td>
                      <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{e.producer?.asset_id || "-"}</td>
                      <td style={{ ...td, fontFamily: "monospace", fontSize: 11, color: "#185FA5" }}>{o.key_id ?? "-"}</td>
                      <td style={td}><span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{o.key_type ?? "-"}</span></td>
                      <td style={td}><span style={{ fontSize: 10, background: o.key_status === "active" ? "#E1F5EE" : "#E6F1FB", color: o.key_status === "active" ? "#085041" : "#0C447C", padding: "2px 6px", borderRadius: 99 }}>{o.key_status ?? "-"}</span></td>
                      <td style={{ ...td, textAlign: "center" }}>{BOOL_CELL(o.approved_storage)}</td>
                      <td style={{ ...td, textAlign: "center" }}>{BOOL_CELL(o.key_rotation_completed)}</td>
                      <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{o.last_rotated_at ? new Date(o.last_rotated_at).toLocaleDateString("ko-KR") : "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 토큰 정책 상태 */}
      {tokenEvents.length > 0 && (
        <div style={card}>
          <p style={cardTitle}>토큰 정책 상태
            <span style={{ fontSize: 11, fontWeight: 400, color: "#73726c", marginLeft: 8 }}>evidence_type: token_policy_state</span>
          </p>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, minWidth: 980 }}>
              <thead>
                <tr>
                  {["타임스탬프", "자산 ID", "인증 방식", "서명 검증", "Issuer", "만료", "JTI registry", "Revocation", "KID 활성"].map((h) => (
                    <th key={h} style={th}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {tokenEvents.map((e) => {
                  const o = e.observed ?? {};
                  return (
                    <tr key={e.evidence_id}>
                      <td style={{ ...td, fontSize: 11, color: "#73726c" }}>
                        {new Date(e.timestamp).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
                      </td>
                      <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{e.producer?.asset_id || "-"}</td>
                      <td style={td}><span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{o.auth_method ?? "-"} {o.algorithm ? `· ${o.algorithm}` : ""}</span></td>
                      <td style={{ ...td, textAlign: "center" }}>{BOOL_CELL(o.validate_signature)}</td>
                      <td style={{ ...td, textAlign: "center" }}>{BOOL_CELL(o.validate_iss)}</td>
                      <td style={{ ...td, textAlign: "center" }}>{BOOL_CELL(o.validate_exp)}</td>
                      <td style={{ ...td, textAlign: "center" }}>{BOOL_CELL(o.validate_jti_registry)}</td>
                      <td style={{ ...td, textAlign: "center" }}>{BOOL_CELL(o.validate_revocation)}</td>
                      <td style={{ ...td, textAlign: "center" }}>{BOOL_CELL(o.validate_kid_active)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 계정 / 권한 상태 */}
      {accountEvents.length > 0 && (
        <div style={card}>
          <p style={cardTitle}>계정 / 권한 상태
            <span style={{ fontSize: 11, fontWeight: 400, color: "#73726c", marginLeft: 8 }}>account_state_event · privileged_access_state</span>
          </p>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, minWidth: 800 }}>
              <thead>
                <tr>
                  {["타임스탬프", "유형", "자산 ID", "Actor", "역할", "IP 클래스", "observed"].map((h) => (
                    <th key={h} style={th}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {accountEvents.map((e) => (
                  <tr key={e.evidence_id}>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>
                      {new Date(e.timestamp).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
                    </td>
                    <td style={td}><span style={{ fontSize: 10, fontFamily: "monospace", color: "#0C447C" }}>{e.evidence_type}</span></td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{e.producer?.asset_id || "-"}</td>
                    <td style={{ ...td, fontSize: 11, color: "#185FA5" }}>{e.actor?.actor_id || "-"}</td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{e.actor?.role || "-"}</td>
                    <td style={td}><span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{e.actor?.source_ip_class || "-"}</span></td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c", fontFamily: "monospace" }}>
                      {e.observed ? Object.entries(e.observed).slice(0, 3).map(([k, v]) => `${k}:${v}`).join("  ") : "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {keyEvents.length === 0 && tokenEvents.length === 0 && accountEvents.length === 0 && (
        <div style={{ ...card, textAlign: "center", padding: "32px 0" }}>
          <p style={{ fontSize: 13, color: "#73726c", margin: "0 0 6px" }}>수집된 Credential Evidence가 없습니다</p>
          <p style={{ fontSize: 11, color: "#b0aea8", margin: 0 }}>key_management_state · token_policy_state · account_state_event 수집 후 표시됩니다</p>
        </div>
      )}
    </div>
  );
}


// ── (2-b) API — evidence_events 기반 (api_authorization_event, gateway_access_event) ──

const DECISION_STYLE = {
  allow:  { bg: "#E6F1FB", text: "#0C447C" },
  block:  { bg: "#E1F5EE", text: "#085041" },
  detect: { bg: "#FFF8E1", text: "#8B6914" },
};

function ApiFromEvidence({ evidenceEvents }) {
  const apiEvents     = evidenceEvents.filter((e) => e.evidence_type === "api_authorization_event");
  const gatewayEvents = evidenceEvents.filter((e) => e.evidence_type === "gateway_access_event");
  const allApiEvents  = [...apiEvents, ...gatewayEvents];

  const allowCount        = allApiEvents.filter((e) => e.access?.decision === "allow").length;
  const blockCount        = allApiEvents.filter((e) => e.access?.decision === "block" || e.access?.decision === "detect").length;
  const missingOwnerCheck = apiEvents.filter((e) => e.control?.owner_check_performed === false).length;
  const missingTenantCheck = apiEvents.filter((e) => e.control?.tenant_check_performed === false).length;

  return (
    <div>
      <SecurityKPI kpis={[
        { label: "총 API 이벤트",        value: allApiEvents.length,  color: "#185FA5", sub: "api_authorization_event + gateway_access_event" },
        { label: "허용 (allow)",           value: allowCount,           color: "#185FA5", sub: "access.decision = allow" },
        { label: "차단/탐지",              value: blockCount,           color: "#0C447C", sub: "block / detect" },
        { label: "소유권 검증 누락",       value: missingOwnerCheck,    color: "#0C447C", sub: "control.owner_check_performed = false" },
        { label: "테넌트 검증 누락",       value: missingTenantCheck,   color: "#0C447C", sub: "control.tenant_check_performed = false" },
      ]} />

      {/* API 인가 이벤트 */}
      {apiEvents.length > 0 && (
        <div style={card}>
          <p style={cardTitle}>API 인가 이벤트
            <span style={{ fontSize: 11, fontWeight: 400, color: "#73726c", marginLeft: 8 }}>evidence_type: api_authorization_event</span>
          </p>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, minWidth: 1100 }}>
              <thead>
                <tr>
                  {["타임스탬프", "자산 ID", "Actor", "Token 테넌트", "Endpoint", "Method", "결정", "Status", "소유권 검증", "테넌트 검증", "AuthZ 서비스"].map((h) => (
                    <th key={h} style={th}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {apiEvents.map((e) => {
                  const dc = DECISION_STYLE[e.access?.decision] || { bg: "#f1efea", text: "#73726c" };
                  return (
                    <tr key={e.evidence_id}>
                      <td style={{ ...td, fontSize: 11, color: "#73726c" }}>
                        {new Date(e.timestamp).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
                      </td>
                      <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{e.producer?.asset_id || "-"}</td>
                      <td style={{ ...td, fontSize: 11, fontWeight: 500, color: "#185FA5" }}>{e.actor?.actor_id || "-"}</td>
                      <td style={{ ...td, fontSize: 11, fontFamily: "monospace", color: "#73726c" }}>{e.token?.token_tenant ?? "-"}</td>
                      <td style={{ ...td, fontSize: 11, fontFamily: "monospace" }}>{e.access?.endpoint || "-"}</td>
                      <td style={td}><span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{e.access?.method || "-"}</span></td>
                      <td style={td}>
                        <span style={{ fontSize: 10, fontWeight: 600, background: dc.bg, color: dc.text, padding: "2px 7px", borderRadius: 99 }}>
                          {e.access?.decision ?? "-"}
                        </span>
                      </td>
                      <td style={{ ...td, textAlign: "center", fontSize: 11 }}>{e.access?.status_code ?? "-"}</td>
                      <td style={{ ...td, textAlign: "center" }}>{BOOL_CELL(e.control?.owner_check_performed)}</td>
                      <td style={{ ...td, textAlign: "center" }}>{BOOL_CELL(e.control?.tenant_check_performed)}</td>
                      <td style={{ ...td, textAlign: "center" }}>{BOOL_CELL(e.control?.authz_service_used)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Gateway 접근 이벤트 */}
      {gatewayEvents.length > 0 && (
        <div style={card}>
          <p style={cardTitle}>Gateway 접근 이벤트
            <span style={{ fontSize: 11, fontWeight: 400, color: "#73726c", marginLeft: 8 }}>evidence_type: gateway_access_event</span>
          </p>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, minWidth: 900 }}>
              <thead>
                <tr>
                  {["타임스탬프", "자산 ID", "Source Zone", "Endpoint", "Method", "결정", "Status", "내부 경로 차단", "WAF"].map((h) => (
                    <th key={h} style={th}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {gatewayEvents.map((e) => {
                  const o  = e.observed ?? {};
                  const dc = DECISION_STYLE[e.access?.decision] || { bg: "#f1efea", text: "#73726c" };
                  return (
                    <tr key={e.evidence_id}>
                      <td style={{ ...td, fontSize: 11, color: "#73726c" }}>
                        {new Date(e.timestamp).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
                      </td>
                      <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{e.producer?.asset_id || "-"}</td>
                      <td style={td}><span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{o.source_zone ?? "-"}</span></td>
                      <td style={{ ...td, fontSize: 11, fontFamily: "monospace" }}>{e.access?.endpoint || "-"}</td>
                      <td style={td}><span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{e.access?.method || "-"}</span></td>
                      <td style={td}>
                        <span style={{ fontSize: 10, fontWeight: 600, background: dc.bg, color: dc.text, padding: "2px 7px", borderRadius: 99 }}>
                          {e.access?.decision ?? "-"}
                        </span>
                      </td>
                      <td style={{ ...td, textAlign: "center", fontSize: 11 }}>{e.access?.status_code ?? "-"}</td>
                      <td style={{ ...td, textAlign: "center" }}>{BOOL_CELL(o.internal_path_blocked)}</td>
                      <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{o.waf_action ?? "-"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {allApiEvents.length === 0 && (
        <div style={{ ...card, textAlign: "center", padding: "32px 0" }}>
          <p style={{ fontSize: 13, color: "#73726c", margin: "0 0 6px" }}>수집된 API Evidence가 없습니다</p>
          <p style={{ fontSize: 11, color: "#b0aea8", margin: 0 }}>api_authorization_event · gateway_access_event 수집 후 표시됩니다</p>
        </div>
      )}
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
                <tr><td colSpan={10} style={{ textAlign: "center", padding: "24px", color: "#b0b0b0", fontSize: 12 }}>소프트웨어 자산이 없습니다</td></tr>
              ) : softwareAssets.map((s) => {
                const ps = PATCH_STYLE[s.patch_status] || {};
                return (
                  <tr key={s.id}>
                    <td style={td}><span style={{ fontWeight: 500, color: "#185FA5" }}>{s.id}</span></td>
                    <td style={{ ...td, fontWeight: 500 }}>{s.name}</td>
                    <td style={td}><span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{s.type}</span></td>
                    <td style={{ ...td, fontFamily: "monospace", fontSize: 11, color: "#444" }}>{s.version}</td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{s.linked_asset}</td>
                    <td style={{ ...td, fontWeight: 700, color: s.cve_count > 0 ? "#0C447C" : "#c0c0c0", textAlign: "center" }}>{s.cve_count > 0 ? s.cve_count : "—"}</td>
                    <td style={td}><span style={{ fontSize: 10, fontWeight: 500, background: ps.bg, color: ps.text, padding: "2px 6px", borderRadius: 99 }}>{s.patch_status}</span></td>
                    <td style={{ ...td, textAlign: "center" }}>
                      {s.eol ? <span style={{ fontSize: 10, fontWeight: 700, background: "#E6F1FB", color: "#0C447C", padding: "2px 6px", borderRadius: 99 }}>EOL</span> : <span style={{ color: "#c0c0c0" }}>—</span>}
                    </td>
                    <td style={{ ...td, fontFamily: "monospace", fontSize: 11, color: "#185FA5" }}>
                      {(s.violation_ids ?? []).length > 0 ? s.violation_ids.join(", ") : <span style={{ color: "#c0c0c0", fontFamily: "inherit" }}>—</span>}
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

  const isVuln = (c) => c.exposed || c.storage === "파일시스템" || c.storage === "환경변수" || ((c.privilege === "최고" || c.privilege === "과다") && !c.mfa) || (c.violation_ids ?? []).length > 0;

  const vulnCount      = credentialAssets.filter(isVuln).length;
  const exposedCount   = credentialAssets.filter((c) => c.exposed).length;
  const expiringCount  = credentialAssets.filter((c) => c.expires_at && new Date(c.expires_at) <= soon).length;
  const overPrivCount  = credentialAssets.filter((c) => c.privilege === "과다" || c.privilege === "최고").length;
  const noMfaCount     = credentialAssets.filter((c) => !c.mfa).length;

  return (
    <div>
      <SecurityKPI kpis={[
        { label: "취약 자격증명",    value: vulnCount,     color: "#0C447C", sub: "외부 노출 · 불안전 보관 · 과도 권한 · 불변식 위반" },
        { label: "노출된 키 / 계정", value: exposedCount,  color: "#0C447C", sub: "외부 노출 확인됨", detail: "즉시 교체 필요" },
        { label: "만료 임박 (90일)", value: expiringCount, color: "#185FA5", sub: "갱신 필요", detail: "서비스 중단 위험" },
        { label: "과도 권한",        value: overPrivCount, color: "#185FA5", sub: "최소 권한 원칙 위반", detail: "최고 · 과다 합산" },
        { label: "MFA 미적용",       value: noMfaCount,    color: "#378ADD", sub: "계정 탈취 시 즉시 침해 가능" },
      ]} />
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
                <tr><td colSpan={11} style={{ textAlign: "center", padding: "24px", color: "#b0b0b0", fontSize: 12 }}>자격증명 자산이 없습니다</td></tr>
              ) : credentialAssets.map((c) => {
                const ss  = CRED_STATUS_STYLE[c.status] || {};
                const stg = STORAGE_STYLE[c.storage]    || {};
                const isExpiringSoon = c.expires_at && new Date(c.expires_at) <= soon;
                return (
                  <tr key={c.id}>
                    <td style={td}><span style={{ fontWeight: 500, color: "#185FA5" }}>{c.id}</span></td>
                    <td style={{ ...td, fontWeight: 500 }}>{c.name}</td>
                    <td style={td}><span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{c.type}</span></td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{c.owner}</td>
                    <td style={td}><span style={{ fontSize: 10, fontWeight: 500, background: stg.bg || "#f1efea", color: stg.text || "#73726c", padding: "2px 6px", borderRadius: 99 }}>{c.storage}</span></td>
                    <td style={{ ...td, textAlign: "center" }}>{c.mfa ? <span style={{ color: "#085041" }}>✓</span> : <span style={{ color: "#E57373", fontWeight: 700 }}>✗</span>}</td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{c.last_rotated}</td>
                    <td style={{ ...td, fontSize: 11, fontWeight: isExpiringSoon ? 600 : 400, color: isExpiringSoon ? "#0C447C" : "#73726c" }}>{c.expires_at ?? "—"}</td>
                    <td style={td}>
                      <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 99, fontWeight: 500, background: c.privilege === "최고" ? "#E6F1FB" : c.privilege === "과다" ? "#EEF4FD" : "#E1F5EE", color: c.privilege === "최고" ? "#0C447C" : c.privilege === "과다" ? "#185FA5" : "#085041" }}>
                        {c.privilege}
                      </span>
                    </td>
                    <td style={{ ...td, textAlign: "center" }}>
                      {c.exposed ? <span style={{ fontSize: 10, fontWeight: 700, background: "#E6F1FB", color: "#0C447C", padding: "2px 6px", borderRadius: 99 }}>노출</span> : <span style={{ color: "#c0c0c0" }}>—</span>}
                    </td>
                    <td style={td}><span style={{ fontSize: 10, fontWeight: 500, background: ss.bg, color: ss.text, padding: "2px 6px", borderRadius: 99 }}>{c.status}</span></td>
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
  const isVulnApi = (a) => a.auth === "없음" || (a.exposed && !a.rate_limit) || (a.exposed && a.auth === "API Key") || (a.violation_ids ?? []).length > 0;

  const vulnCount        = apiAssets.filter(isVulnApi).length;
  const exposedCount     = apiAssets.filter((a) => a.exposed).length;
  const noAuthCount      = apiAssets.filter((a) => a.auth === "없음").length;
  const noRateLimitCount = apiAssets.filter((a) => !a.rate_limit).length;

  return (
    <div>
      <SecurityKPI kpis={[
        { label: "취약 API",          value: vulnCount,        color: "#0C447C", sub: "인증 없음 · 외부 노출 + Rate Limit 미적용 · 불변식 위반" },
        { label: "외부 노출 API",     value: exposedCount,     color: "#0C447C", sub: "인터넷 직접 노출", detail: "외부 접근 가능" },
        { label: "인증 없는 API",     value: noAuthCount,      color: "#185FA5", sub: "무인증 접근 가능", detail: "즉각 침해 위험" },
        { label: "Rate Limit 미적용", value: noRateLimitCount, color: "#185FA5", sub: "DoS 공격 취약",    detail: "요청 제한 없음" },
      ]} />
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
                <tr><td colSpan={9} style={{ textAlign: "center", padding: "24px", color: "#b0b0b0", fontSize: 12 }}>API 자산이 없습니다</td></tr>
              ) : apiAssets.map((a) => {
                const sc = SCOPE_STYLE[a.scope] || {};
                return (
                  <tr key={a.id}>
                    <td style={td}><span style={{ fontWeight: 500, color: "#185FA5" }}>{a.id}</span></td>
                    <td style={{ ...td, fontWeight: 500 }}>{a.name}</td>
                    <td style={td}><span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{a.type}</span></td>
                    <td style={{ ...td, fontFamily: "monospace", fontSize: 11, color: "#73726c" }}>{a.endpoint}</td>
                    <td style={td}>
                      <span style={{ fontSize: 10, fontWeight: 500, padding: "2px 6px", borderRadius: 99, background: a.auth === "없음" ? "#E6F1FB" : "#E1F5EE", color: a.auth === "없음" ? "#0C447C" : "#085041" }}>
                        {a.auth}
                      </span>
                    </td>
                    <td style={td}><span style={{ fontSize: 10, background: sc.bg || "#f1efea", color: sc.text || "#73726c", padding: "2px 6px", borderRadius: 99 }}>{a.scope}</span></td>
                    <td style={{ ...td, textAlign: "center" }}>{a.rate_limit ? <span style={{ color: "#085041" }}>✓</span> : <span style={{ color: "#E57373", fontWeight: 700 }}>✗</span>}</td>
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

// ── (5) 서비스 탭 ─────────────────────────────────────────────────────────────

function ServiceSection({ services }) {
  const unreg = services.filter((s) => s.observation_status === "unregistered_service_candidate").length;
  const wazuh = services.filter((s) => s.collected_by_wazuh).length;

  const COMP_STYLE = {
    application_api: { bg: "#EEF4FD", text: "#185FA5" },
    database:        { bg: "#E6F1FB", text: "#0C447C" },
    siem:            { bg: "#E1F5EE", text: "#085041" },
    signing_service: { bg: "#FFF8E1", text: "#8B6914" },
    auth_service:    { bg: "#F0F6FE", text: "#378ADD" },
    state_collector: { bg: "#f1efea", text: "#73726c" },
  };

  return (
    <div>
      <SecurityKPI kpis={[
        { label: "총 서비스",     value: services.length, color: "#185FA5", sub: "등록된 모든 서비스" },
        { label: "미등록 서비스", value: unreg,           color: "#0C447C", sub: "unregistered_service_candidate", detail: unreg > 0 ? "검토 필요" : "" },
        { label: "Wazuh 수집",    value: wazuh,           color: "#085041", sub: "Wazuh 에이전트 수집 중" },
      ]} />
      <div style={card}>
        <p style={cardTitle}>서비스 목록
          <span style={{ fontSize: 11, fontWeight: 400, color: "#73726c", marginLeft: 8 }}>asset_id → service_id → evidence_id 추적 기준</span>
        </p>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, minWidth: 900 }}>
            <thead>
              <tr>
                {["Service ID", "이름", "소유 자산", "VM", "Zone", "Component 유형", "Wazuh 수집", "관측 상태"].map((h) => (
                  <th key={h} style={th}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {services.length === 0 ? (
                <tr><td colSpan={8} style={{ textAlign: "center", padding: "24px", color: "#b0b0b0", fontSize: 12 }}>서비스 데이터가 없습니다</td></tr>
              ) : services.map((s) => {
                const cs  = COMP_STYLE[s.component_type] || { bg: "#f1efea", text: "#73726c" };
                const obs = OBS_STATUS_STYLE[s.observation_status] || {};
                return (
                  <tr key={s.service_id}>
                    <td style={td}><span style={{ fontWeight: 500, color: "#185FA5", fontFamily: "monospace", fontSize: 11 }}>{s.service_id}</span></td>
                    <td style={{ ...td, fontWeight: 500 }}>{s.name}</td>
                    <td style={{ ...td, fontFamily: "monospace", fontSize: 11, color: "#73726c" }}>{s.owning_asset}</td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{s.vm}</td>
                    <td style={td}>
                      <span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{s.zone}</span>
                    </td>
                    <td style={td}>
                      <span style={{ fontSize: 10, background: cs.bg, color: cs.text, padding: "1px 6px", borderRadius: 99 }}>{s.component_type}</span>
                    </td>
                    <td style={{ ...td, textAlign: "center" }}>{s.collected_by_wazuh ? <span style={{ color: "#085041" }}>✓</span> : <span style={{ color: "#c0c0c0" }}>—</span>}</td>
                    <td style={td}>
                      <span style={{ fontSize: 10, fontWeight: 500, background: obs.bg, color: obs.text, padding: "2px 6px", borderRadius: 99 }}>
                        {obs.label || s.observation_status}
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

// ── (6) Evidence 탭 ───────────────────────────────────────────────────────────

function EvidenceSection({ evidenceEvents }) {
  const [selectedEvidence, setSelectedEvidence] = useState(null);

  const attackCount = evidenceEvents.filter((e) => e.event_category === "attack_execution").length;
  const envCount    = evidenceEvents.filter((e) => e.event_category === "environment_state").length;

  return (
    <div>
      <SecurityKPI kpis={[
        { label: "총 Evidence",     value: evidenceEvents.length, color: "#185FA5", sub: "수집된 정규화 Evidence" },
        { label: "공격 실행",       value: attackCount,           color: "#0C447C", sub: "attack_execution 카테고리" },
        { label: "환경 상태",       value: envCount,              color: "#378ADD", sub: "environment_state 카테고리" },
      ]} />
      <div style={card}>
        <p style={cardTitle}>Evidence 목록
          <span style={{ fontSize: 11, fontWeight: 400, color: "#73726c", marginLeft: 8 }}>evidence_id → invariant_id 연결 기준</span>
        </p>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, minWidth: 960 }}>
            <thead>
              <tr>
                {["Evidence ID", "타임스탬프", "카테고리", "Evidence 유형", "VM", "자산 ID", "서비스 ID", "Endpoint", "결정", ""].map((h) => (
                  <th key={h} style={th}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {evidenceEvents.length === 0 ? (
                <tr><td colSpan={10} style={{ textAlign: "center", padding: "24px", color: "#b0b0b0", fontSize: 12 }}>수집된 Evidence가 없습니다</td></tr>
              ) : evidenceEvents.map((e) => {
                const cat = EVT_CAT_STYLE[e.event_category] || {};
                return (
                  <tr key={e.evidence_id} style={{ cursor: "pointer" }} onClick={() => setSelectedEvidence(selectedEvidence?.evidence_id === e.evidence_id ? null : e)}>
                    <td style={td}><span style={{ fontWeight: 500, color: "#185FA5", fontFamily: "monospace", fontSize: 11 }}>{e.evidence_id}</span></td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>
                      {new Date(e.timestamp).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
                    </td>
                    <td style={td}>
                      <span style={{ fontSize: 10, background: cat.bg, color: cat.text, padding: "1px 6px", borderRadius: 99 }}>{cat.label || e.event_category}</span>
                    </td>
                    <td style={{ ...td, fontSize: 11, fontFamily: "monospace", color: "#0C447C" }}>{e.evidence_type}</td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{e.producer?.vm || "-"}</td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{e.producer?.asset_id || "-"}</td>
                    <td style={{ ...td, fontSize: 11, color: "#73726c" }}>{e.producer?.service_id || "-"}</td>
                    <td style={{ ...td, fontSize: 11, fontFamily: "monospace" }}>{e.access?.endpoint || "-"}</td>
                    <td style={td}>
                      {e.access?.decision
                        ? <span style={{ fontSize: 10, fontWeight: 600, background: e.access.decision === "allow" ? "#E6F1FB" : "#E1F5EE", color: e.access.decision === "allow" ? "#0C447C" : "#085041", padding: "1px 7px", borderRadius: 99 }}>{e.access.decision}</span>
                        : <span style={{ color: "#c0c0c0" }}>—</span>}
                    </td>
                    <td style={{ ...td, textAlign: "right" }}>
                      <span style={{ fontSize: 10, color: "#185FA5" }}>{selectedEvidence?.evidence_id === e.evidence_id ? "접기 ▲" : "상세 ▼"}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {selectedEvidence && (
          <div style={{ marginTop: 12, background: "#f8fafc", border: "0.5px solid rgba(0,0,0,0.08)", borderRadius: 8, padding: 14 }}>
            {/* 헤더 */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <span style={{ fontSize: 12, fontWeight: 600, color: "#0C447C", fontFamily: "monospace" }}>{selectedEvidence.evidence_id}</span>
              <span style={{ fontSize: 11, color: "#73726c" }}>trace_id: {selectedEvidence.trace_id} · request_id: {selectedEvidence.request_id}</span>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginBottom: 10 }}>
              {/* Actor */}
              {selectedEvidence.actor && (
                <div style={{ background: "#fff", border: "0.5px solid rgba(0,0,0,0.08)", borderRadius: 7, padding: "10px 12px" }}>
                  <p style={detailSectionLabel}>Actor</p>
                  <DetailRow k="actor_id"       v={selectedEvidence.actor.actor_id} />
                  <DetailRow k="role"            v={selectedEvidence.actor.role} />
                  <DetailRow k="source_ip_class" v={selectedEvidence.actor.source_ip_class} />
                </div>
              )}

              {/* Token (유효성 불리언만, 원문 없음) */}
              {selectedEvidence.token && (
                <div style={{ background: "#fff", border: "0.5px solid rgba(0,0,0,0.08)", borderRadius: 7, padding: "10px 12px" }}>
                  <p style={detailSectionLabel}>Token 검증 상태</p>
                  <DetailRow k="token_sub"            v={selectedEvidence.token.token_sub} />
                  <DetailRow k="token_tenant"         v={selectedEvidence.token.token_tenant} />
                  <DetailRow k="signature_valid"      v={String(selectedEvidence.token.signature_valid)} />
                  <DetailRow k="issued_by_auth_server" v={String(selectedEvidence.token.issued_by_auth_server)} />
                  <DetailRow k="revoked"              v={String(selectedEvidence.token.revoked)} />
                </div>
              )}

              {/* Target */}
              {selectedEvidence.target?.asset_id && (
                <div style={{ background: "#fff", border: "0.5px solid rgba(0,0,0,0.08)", borderRadius: 7, padding: "10px 12px" }}>
                  <p style={detailSectionLabel}>Target 자산</p>
                  <DetailRow k="asset_id"   v={selectedEvidence.target.asset_id} />
                  <DetailRow k="asset_type" v={selectedEvidence.target.asset_type} />
                  <DetailRow k="owner_id"   v={selectedEvidence.target.owner_id} />
                  <DetailRow k="tenant_id"  v={selectedEvidence.target.tenant_id} />
                </div>
              )}
            </div>

            {/* Control (보안 검증 수행 여부 — 불변식 판단 핵심) */}
            {selectedEvidence.control && (
              <div style={{ background: "#fff", border: "0.5px solid rgba(0,0,0,0.08)", borderRadius: 7, padding: "10px 12px", marginBottom: 10 }}>
                <p style={detailSectionLabel}>Control — 보안 검증 수행 여부</p>
                <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
                  {[
                    ["owner_check_performed",  selectedEvidence.control.owner_check_performed],
                    ["tenant_check_performed", selectedEvidence.control.tenant_check_performed],
                    ["authz_service_used",     selectedEvidence.control.authz_service_used],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ fontSize: 11, color: "#73726c" }}>{k}</span>
                      {BOOL_CELL(v)}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Observed */}
            {selectedEvidence.observed && (
              <div style={{ marginBottom: 10 }}>
                <p style={detailSectionLabel}>Observed 필드</p>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {Object.entries(selectedEvidence.observed).map(([k, v]) => (
                    <div key={k} style={{ fontSize: 11, background: "#fff", border: "0.5px solid rgba(0,0,0,0.08)", borderRadius: 6, padding: "3px 8px" }}>
                      <span style={{ color: "#73726c" }}>{k}: </span>
                      <span style={{ color: "#1a1a18", fontFamily: typeof v === "boolean" ? "inherit" : "monospace" }}>{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Raw ref */}
            {selectedEvidence.raw_ref && (
              <div style={{ fontSize: 11, color: "#73726c" }}>
                원본 로그: {selectedEvidence.raw_ref.source} · agent: {selectedEvidence.raw_ref.agent} · {selectedEvidence.raw_ref.location} · log_id: {selectedEvidence.raw_ref.log_id}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── (공통) 정책 카드 + 이벤트 피드 + 전체 자산 목록 ─────────────────────────

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
            const linkedIds = pol.related_invariant_ids || pol.linked_violations || [];
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
                <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: linkedIds.length > 0 ? 6 : 0 }}>
                  <span style={{ fontSize: 12, color: ps.text, fontWeight: 700 }}>위반 자산 {pol.violating_assets.length}대</span>
                  <span style={{ fontSize: 10, color: "#73726c" }}>
                    — {pol.violating_assets.slice(0, 2).join(", ")}{pol.violating_assets.length > 2 ? ` 외 ${pol.violating_assets.length - 2}건` : ""}
                  </span>
                </div>
                {linkedIds.length > 0 && (
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {linkedIds.map((v) => (
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
      {assetEvents.length === 0 ? (
        <div style={{ padding: "24px 0", textAlign: "center" }}>
          <p style={{ fontSize: 13, color: "#73726c", margin: "0 0 6px" }}>탐지된 이벤트가 없습니다</p>
        </div>
      ) : (
        <>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            {visible.map((evt) => {
              const ts = EVT_TYPE_STYLE[evt.type] || {};
              const ss = SEV_STYLE[evt.severity]  || {};
              return (
                <div key={evt.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 10px", border: "0.5px solid rgba(0,0,0,0.07)", borderRadius: 7, background: "#fafbfc" }}>
                  <span style={{ fontSize: 9, fontWeight: 600, background: ts.bg, color: ts.text, padding: "2px 7px", borderRadius: 99, flexShrink: 0 }}>{evt.type}</span>
                  <span style={{ fontSize: 12, color: "#1a1a18", flex: 1 }}>{evt.desc}</span>
                  <span style={{ fontSize: 10, color: "#73726c", flexShrink: 0 }}>{evt.zone}</span>
                  <span style={{ fontSize: 9, fontWeight: 600, background: ss.bg, color: ss.text, padding: "2px 7px", borderRadius: 99, flexShrink: 0 }}>{evt.severity}</span>
                  <span style={{ fontSize: 10, color: "#b0b0b0", flexShrink: 0 }}>
                    {new Date(evt.time).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
                  </span>
                </div>
              );
            })}
          </div>
          {assetEvents.length > 5 && (
            <button onClick={() => setShowAll((v) => !v)} style={{ marginTop: 10, background: "none", border: "0.5px solid rgba(0,0,0,0.12)", borderRadius: 6, cursor: "pointer", fontSize: 11, color: "#73726c", padding: "4px 12px" }}>
              {showAll ? "접기 ▲" : `더 보기 (${assetEvents.length - 5}건) ▼`}
            </button>
          )}
        </>
      )}
    </div>
  );
}

// [비활성] software_assets / credential_assets / api_assets 관련 카테고리는
//   schema.sql에서 비활성 처리 — 필요 시 props와 rows 배열 추가
function AssetOverviewTable({ assets }) {
  const CATEGORY_STYLE = {
    Hardware: { bg: "#E6F1FB", text: "#0C447C" },
    // Software:   { bg: "#F0F6FE", text: "#378ADD" },  // [비활성]
    // Credential: { bg: "#FFF8E1", text: "#8B6914" },  // [비활성]
    // API:        { bg: "#E1F5EE", text: "#085041" },  // [비활성]
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
      id: assetId(a), name: assetName(a), subType: assetType(a),
      patchStatus: a.patch_status,
      violationCount: assetViolations(a).length,
      status: a.status,
      onlineStatus: a.online_status,
    })),
    // [비활성] software_assets rows — 필요 시 활성화
    // [비활성] credential_assets rows — 필요 시 활성화
    // [비활성] api_assets rows — 필요 시 활성화
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
                  <td style={td}><span style={{ fontSize: 10, fontWeight: 500, background: cs.bg, color: cs.text, padding: "1px 7px", borderRadius: 99 }}>{row.category}</span></td>
                  <td style={{ ...td, fontFamily: "monospace", fontSize: 11, color: "#185FA5" }}>{row.id}</td>
                  <td style={{ ...td, fontWeight: 500 }}>
                    {row.onlineStatus !== null ? (
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                        <span style={{ width: 6, height: 6, borderRadius: "50%", background: row.onlineStatus === "온라인" ? "#1D9E75" : "#b0b0b0", flexShrink: 0 }} />
                        {row.name}
                      </span>
                    ) : row.name}
                  </td>
                  <td style={td}><span style={{ fontSize: 10, background: "#f1efea", color: "#73726c", padding: "1px 6px", borderRadius: 99 }}>{row.subType}</span></td>
                  <td style={td}>
                    {row.patchStatus
                      ? <span style={{ fontSize: 10, fontWeight: 500, background: ps.bg, color: ps.text, padding: "2px 6px", borderRadius: 99 }}>{row.patchStatus}</span>
                      : <span style={{ color: "#c0c0c0" }}>—</span>}
                  </td>
                  <td style={{ ...td, textAlign: "center" }}>
                    {row.violationCount > 0 ? <span style={{ fontWeight: 700, color: "#0C447C" }}>{row.violationCount}</span> : <span style={{ color: "#c0c0c0" }}>—</span>}
                  </td>
                  <td style={td}><span style={{ fontSize: 10, fontWeight: 500, background: ss.bg, color: ss.text, padding: "2px 6px", borderRadius: 99 }}>{row.status}</span></td>
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

export default function AssetSection({ assets, assetHistory, services, evidenceEvents }) {
  const [activeCategory, setActiveCategory] = useState("전체");

  const safeAssets     = assets         ?? [];
  const enrichedAssets = safeAssets.map((a) => ({ ...a, status: deriveAssetStatus(a) }));
  const safeHistory    = assetHistory   ?? [];  // scan_asset_snapshot 기반 추이 데이터
  const safeServices   = services       ?? [];
  const safeEvidence   = evidenceEvents ?? [];
  // 비활성 props (schema.sql 주석 처리된 테이블 — 필요 시 props/signature에 추가)
  // const safeEvents     = assetEvents      ?? [];  // [비활성] asset_events
  // const safePolicies   = assetPolicies    ?? [];  // [비활성] invariant_impact
  // const safeSoftware   = softwareAssets   ?? [];  // [비활성] software_assets
  // const safeCredential = credentialAssets ?? [];  // [비활성] credential_assets
  // const safeApi        = apiAssets        ?? [];  // [비활성] api_assets

  return (
    <div>
      {/* 카테고리 탭 */}
      <div style={{ display: "flex", gap: 6, marginBottom: 24, flexWrap: "wrap" }}>
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

      {/* 전체 탭 */}
      {activeCategory === "전체" && (
        <>
          <SubLabel>카테고리별 현황</SubLabel>
          <CategorySummaryCards
            assets={enrichedAssets}
            services={safeServices}
            onCategoryClick={setActiveCategory}
          />
          <TrendCharts assetHistory={safeHistory} />
          <SubLabel>전체 자산</SubLabel>
          <AssetOverviewTable assets={enrichedAssets} />
        </>
      )}

      {/* Hardware 탭 */}
      {activeCategory === "hardware" && (
        <>
          <SubLabel>자산 인벤토리</SubLabel>
          <InventoryCards assets={enrichedAssets} />
          <SubLabel>보안 상태 KPI — assets 테이블 기준 (null이면 파이프라인 미수집)</SubLabel>
          <SecurityKPI kpis={[
            {
              label: "불변식 위반 자산",
              color: "#0C447C",
              sub:   "violation_assets 연결 자산 수",
              value: enrichedAssets.filter((a) => assetViolations(a).length > 0).length,
            },
            {
              label: "공격 이벤트 자산",
              color: "#185FA5",
              sub:   "evidence_events attack_execution 기록 보유 자산",
              value: enrichedAssets.filter((a) => {
                const ev = buildEvidenceStatsByAsset(safeEvidence)[assetId(a)];
                return ev && ev.attack > 0;
              }).length,
            },
            {
              label: "미등록 후보",
              color: "#378ADD",
              sub:   "observation_status = unregistered_asset_candidate",
              value: enrichedAssets.filter((a) => assetObsStatus(a) === "unregistered_asset_candidate").length,
            },
          ]} />
          <SubLabel>하드웨어 자산 목록</SubLabel>
          <AssetList assets={enrichedAssets} evidenceEvents={safeEvidence} />
        </>
      )}

      {/* [비활성] software_assets 테이블 미구현 */}
      {/* {activeCategory === "software" && <SoftwareSection softwareAssets={safeSoftware} />} */}

      {/* Credential — evidence_events(key_management_state, token_policy_state, account_state_event) 기반 */}
      {activeCategory === "credential" && (
        <>
          <SubLabel>Credential · 키 · 토큰 정책 — evidence_events 기반</SubLabel>
          <CredentialFromEvidence evidenceEvents={safeEvidence} />
        </>
      )}

      {/* API — evidence_events(api_authorization_event, gateway_access_event) 기반 */}
      {activeCategory === "api" && (
        <>
          <SubLabel>API 접근 · 인가 현황 — evidence_events 기반</SubLabel>
          <ApiFromEvidence evidenceEvents={safeEvidence} />
        </>
      )}

      {/* 서비스 탭 */}
      {activeCategory === "service" && (
        <>
          <SubLabel>서비스 목록 — asset_id → service_id → evidence_id 추적</SubLabel>
          <ServiceSection services={safeServices} />
          {/* [비활성] PolicyCards — invariant_impact 테이블 미구현 */}
          {/* <SubLabel>정책 위반 현황</SubLabel> */}
          {/* <PolicyCards assetPolicies={safePolicies} /> */}
        </>
      )}

      {/* Evidence 탭 */}
      {activeCategory === "evidence" && (
        <>
          <SubLabel>Evidence 목록 — 정규화 Evidence 직접 탐색</SubLabel>
          <EvidenceSection evidenceEvents={safeEvidence} />
          {/* [비활성] EventFeed — asset_events 테이블 미구현 */}
          {/* <SubLabel>탐지 이벤트</SubLabel> */}
          {/* <EventFeed assetEvents={safeEvents} /> */}
        </>
      )}
    </div>
  );
}

// ── 스타일 상수 ───────────────────────────────────────────────────────────────

const detailSectionLabel = {
  fontSize: 10, fontWeight: 600, color: "#73726c",
  textTransform: "uppercase", letterSpacing: "0.05em", margin: "0 0 7px",
};

function DetailRow({ k, v }) {
  if (v === null || v === undefined || v === "null" || v === "undefined") return null;
  return (
    <div style={{ display: "flex", gap: 6, marginBottom: 3, fontSize: 11 }}>
      <span style={{ color: "#73726c", flexShrink: 0 }}>{k}:</span>
      <span style={{ color: "#1a1a18", fontFamily: "monospace", wordBreak: "break-all" }}>{String(v)}</span>
    </div>
  );
}

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
