import { useState, useEffect, useRef } from "react";

const SCAN_STEPS = [
  { label: "자산 수집",          range: [0,  25]  },
  { label: "취약점 분석",         range: [25, 60]  },
  { label: "시나리오 생성",        range: [60, 85]  },
  { label: "보고서 생성",          range: [85, 100] },
];

function scoreColor(score) {
  if (score >= 70) return "#1D9E75";
  if (score >= 50) return "#E8A838";
  return "#E05A5A";
}

function getCurrentStep(progress) {
  return (
    SCAN_STEPS.find((s) => progress >= s.range[0] && progress < s.range[1]) ??
    SCAN_STEPS[SCAN_STEPS.length - 1]
  );
}

export default function ScanSection({ scanList, selectedScanId, onSelectScan }) {
  const [status, setStatus]     = useState("idle"); // "idle" | "running" | "done"
  const [progress, setProgress] = useState(0);
  const timerRef                = useRef(null);

  // 가짜 진행률 애니메이션 — 백엔드 연동 후 실제 API 폴링으로 교체
  useEffect(() => {
    if (status !== "running") return;
    timerRef.current = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(timerRef.current);
          setStatus("done");
          return 100;
        }
        return prev + 1;
      });
    }, 80); // ~8초에 100%
    return () => clearInterval(timerRef.current);
  }, [status]);

  const handleStart = () => {
    setStatus("running");
    setProgress(0);
  };

  const handleReset = () => {
    setStatus("idle");
    setProgress(0);
  };

  const currentStep = status === "running" ? getCurrentStep(progress) : null;

  return (
    <div>
      <p style={sectionLabel}>점검 관리</p>

      {/* ── 새 점검 시작 (대기 상태) ─────────────────────────────── */}
      {status === "idle" && (
        <div style={card}>
          <p style={cardTitle}>새 점검 시작</p>
          <div style={{ display: "flex", gap: 12, marginBottom: 14 }}>
            <div style={{ flex: 1 }}>
              <p style={fieldLabel}>점검 대상</p>
              <div style={fieldBox}>전체 자산 (20개)</div>
            </div>
            <div style={{ flex: 1 }}>
              <p style={fieldLabel}>점검 유형</p>
              <div style={fieldBox}>전체 점검</div>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <p style={{ fontSize: 11, color: "#b0aea8", margin: 0 }}>
              * 백엔드 연동 전 UI 미리보기용. 실제 점검은 수행 x
            </p>
            <button onClick={handleStart} style={primaryBtn}>점검 시작</button>
          </div>
        </div>
      )}

      {/* ── 점검 진행 중 ─────────────────────────────────────────── */}
      {status === "running" && (
        <div style={card}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
            <div>
              <p style={{ ...cardTitle, margin: "0 0 4px" }}>점검 진행 중</p>
              <p style={{ fontSize: 11, color: "#73726c", margin: 0 }}>
                {currentStep?.label} 중...
              </p>
            </div>
            <span style={{ fontSize: 22, fontWeight: 600, color: "#0C447C" }}>{progress}%</span>
          </div>

          {/* 전체 진행 바 */}
          <div style={{ height: 6, background: "#f1efea", borderRadius: 99, overflow: "hidden", marginBottom: 16 }}>
            <div style={{
              height: "100%", width: `${progress}%`,
              background: "linear-gradient(90deg, #185FA5, #0C447C)",
              borderRadius: 99, transition: "width 0.1s linear",
            }} />
          </div>

          {/* 단계별 상태 */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 6 }}>
            {SCAN_STEPS.map((step, i) => {
              const done   = progress >= step.range[1];
              const active = progress >= step.range[0] && progress < step.range[1];
              return (
                <div key={i} style={{
                  padding: "8px 6px", borderRadius: 8, textAlign: "center",
                  background: done ? "#E6F1FB" : active ? "#f0f6fc" : "#f5f5f3",
                  border: active ? "0.5px solid #185FA5" : "0.5px solid transparent",
                  transition: "all 0.3s",
                }}>
                  <div style={{ fontSize: 12, marginBottom: 3 }}>
                    {done ? "✓" : active ? "⋯" : "○"}
                  </div>
                  <p style={{
                    fontSize: 10, margin: 0,
                    fontWeight: active || done ? 500 : 400,
                    color: done ? "#0C447C" : active ? "#185FA5" : "#b0aea8",
                  }}>
                    {step.label}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── 점검 완료 ────────────────────────────────────────────── */}
      {status === "done" && (
        <div style={{ ...card, background: "#E6F1FB", border: "0.5px solid #c8ddf0" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <p style={{ fontSize: 13, fontWeight: 600, color: "#0C447C", margin: "0 0 4px" }}>
                점검 완료
              </p>
              <p style={{ fontSize: 11, color: "#185FA5", margin: 0 }}>
                백엔드 연동 후 결과가 이력에 자동으로 추가됩니다.
              </p>
            </div>
            <button onClick={handleReset} style={ghostBtn}>새 점검</button>
          </div>
        </div>
      )}

      {/* ── 점검 이력 ────────────────────────────────────────────── */}
      <div style={card}>
        <p style={cardTitle}>점검 이력</p>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              {["스캔 ID", "점검 일시", "보안 점수", "총 취약점", "Critical/High", "패치율", ""].map((h) => (
                <th key={h} style={{
                  fontSize: 10, fontWeight: 500, color: "#73726c", textAlign: "left",
                  padding: "0 10px 10px", borderBottom: "0.5px solid rgba(0,0,0,0.08)",
                }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[...scanList].reverse().map((scan) => {
              const isSelected = scan.scan_id === selectedScanId;
              return (
                <tr key={scan.scan_id} style={{ background: isSelected ? "#f0f6fc" : "transparent" }}>
                  <td style={td}>
                    <span style={{ fontSize: 12, fontWeight: isSelected ? 600 : 400, color: "#1a1a18" }}>
                      {scan.scan_id}
                    </span>
                  </td>
                  <td style={td}>
                    <span style={{ fontSize: 11, color: "#73726c" }}>
                      {new Date(scan.scanned_at).toLocaleDateString("ko-KR", { year: "numeric", month: "short", day: "numeric" })}
                    </span>
                  </td>
                  <td style={td}>
                    <span style={{ fontSize: 14, fontWeight: 600, color: scoreColor(scan.metrics.score) }}>
                      {scan.metrics.score}
                    </span>
                  </td>
                  <td style={td}>
                    <span style={{ fontSize: 12, color: "#1a1a18" }}>{scan.metrics.total_violations}건</span>
                  </td>
                  <td style={td}>
                    <span style={{ fontSize: 12, color: "#1a1a18" }}>{scan.metrics.critical_high}건</span>
                  </td>
                  <td style={td}>
                    <span style={{ fontSize: 12, color: "#1a1a18" }}>{scan.metrics.patch_rate}%</span>
                  </td>
                  <td style={td}>
                    {isSelected ? (
                      <span style={{
                        fontSize: 10, fontWeight: 500,
                        background: "#E6F1FB", color: "#0C447C",
                        padding: "2px 10px", borderRadius: 99,
                      }}>
                        현재 선택
                      </span>
                    ) : (
                      <button
                        onClick={() => onSelectScan(scan.scan_id)}
                        style={ghostBtn}
                      >
                        선택
                      </button>
                    )}
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

const sectionLabel = { fontSize: 11, fontWeight: 500, color: "#73726c", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 10 };
const card         = { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, padding: 16, marginBottom: 12 };
const cardTitle    = { fontSize: 13, fontWeight: 500, marginBottom: 12 };
const fieldLabel   = { fontSize: 11, color: "#73726c", margin: "0 0 4px" };
const fieldBox     = { padding: "7px 12px", fontSize: 12, borderRadius: 8, border: "0.5px solid rgba(0,0,0,0.12)", color: "#1a1a18", background: "#fafaf9" };
const td           = { padding: "10px 10px", borderBottom: "0.5px solid rgba(0,0,0,0.06)", verticalAlign: "middle" };
const primaryBtn   = { padding: "8px 18px", fontSize: 12, fontWeight: 600, borderRadius: 8, border: "none", background: "#0C447C", color: "#fff", cursor: "pointer" };
const ghostBtn     = { padding: "5px 12px", fontSize: 11, borderRadius: 99, border: "0.5px solid rgba(0,0,0,0.15)", background: "transparent", color: "#73726c", cursor: "pointer" };
