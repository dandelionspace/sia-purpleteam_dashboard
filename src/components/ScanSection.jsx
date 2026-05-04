import { useState, useEffect, useRef } from "react";
import { triggerScan, USE_MOCK } from "../services/scanService";

// 보고서 생성 단계 제거 — 3단계로 구성
const SCAN_STEPS = [
  { label: "자산 수집",    range: [0,  33] },
  { label: "취약점 분석",  range: [33, 70] },
  { label: "시나리오 생성", range: [70, 100] },
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

export default function ScanSection({ scanList, selectedScanId, onSelectScan, onRefresh }) {
  const [status, setStatus]           = useState("idle"); // "idle" | "running" | "done" | "error"
  const [progress, setProgress]       = useState(0);
  const [pendingScanId, setPendingScanId] = useState(null);
  const progressTimer = useRef(null);
  const pollTimer     = useRef(null);

  // 진행 바: 90%까지 서서히 전진 (약 30초), 완료 신호 오면 100%로 점프
  useEffect(() => {
    if (status !== "running") return;
    progressTimer.current = setInterval(() => {
      setProgress((prev) => (prev < 90 ? prev + 1 : prev));
    }, 333); // 90% 도달에 ~30초
    return () => clearInterval(progressTimer.current);
  }, [status]);

  // 실제 API 폴링: 2초마다 스캔 목록 갱신 요청
  useEffect(() => {
    if (status !== "running" || USE_MOCK || !pendingScanId) return;
    pollTimer.current = setInterval(() => {
      onRefresh?.();
    }, 2000);
    return () => clearInterval(pollTimer.current);
  }, [status, pendingScanId, onRefresh]);

  // scanList에서 완료 여부 감지
  useEffect(() => {
    if (!pendingScanId || status !== "running") return;
    const found = scanList.find((s) => s.scan_id === pendingScanId);
    if (found?.status === "completed") {
      clearInterval(progressTimer.current);
      clearInterval(pollTimer.current);
      setProgress(100);
      setStatus("done");
      onSelectScan?.(pendingScanId);
    }
  }, [scanList, pendingScanId, status, onSelectScan]);

  const handleStart = async () => {
    setStatus("running");
    setProgress(0);
    setPendingScanId(null);

    if (USE_MOCK) {
      // Mock 모드: 8초 애니메이션 후 자동 완료
      let p = 0;
      clearInterval(progressTimer.current);
      progressTimer.current = setInterval(() => {
        p += 1;
        setProgress(p);
        if (p >= 100) {
          clearInterval(progressTimer.current);
          setStatus("done");
        }
      }, 80);
      return;
    }

    try {
      const { scan_id } = await triggerScan();
      setPendingScanId(scan_id);
    } catch (err) {
      console.error("스캔 트리거 실패:", err);
      setStatus("error");
      clearInterval(progressTimer.current);
    }
  };

  const handleReset = () => {
    clearInterval(progressTimer.current);
    clearInterval(pollTimer.current);
    setStatus("idle");
    setProgress(0);
    setPendingScanId(null);
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
              <div style={fieldBox}>전체 자산</div>
            </div>
            <div style={{ flex: 1 }}>
              <p style={fieldLabel}>점검 유형</p>
              <div style={fieldBox}>전체 점검</div>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <p style={{ fontSize: 11, color: "#b0aea8", margin: 0 }}>
              {USE_MOCK ? "* mock 모드 — 실제 스캔 미수행" : "* Wazuh · DB · MinIO 데이터를 수집합니다"}
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
              borderRadius: 99, transition: "width 0.3s linear",
            }} />
          </div>

          {/* 단계별 상태 — 3단계 */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6 }}>
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
                {pendingScanId
                  ? `${pendingScanId} 결과가 이력에 추가됐습니다.`
                  : "결과가 이력에 추가됐습니다."}
              </p>
            </div>
            <button onClick={handleReset} style={ghostBtn}>새 점검</button>
          </div>
        </div>
      )}

      {/* ── 오류 ─────────────────────────────────────────────────── */}
      {status === "error" && (
        <div style={{ ...card, background: "#FEF2F2", border: "0.5px solid #FECACA" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <p style={{ fontSize: 13, fontWeight: 600, color: "#991B1B", margin: "0 0 4px" }}>
                스캔 시작 실패
              </p>
              <p style={{ fontSize: 11, color: "#B91C1C", margin: 0 }}>
                백엔드 서버에 연결할 수 없습니다. 연결 상태를 확인하세요.
              </p>
            </div>
            <button onClick={handleReset} style={ghostBtn}>재시도</button>
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
              const isRunning  = scan.status === "running";
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
                    {isRunning ? (
                      <span style={{ fontSize: 11, color: "#E8A838" }}>진행 중</span>
                    ) : (
                      <span style={{ fontSize: 14, fontWeight: 600, color: scoreColor(scan.metrics.score) }}>
                        {scan.metrics.score}
                      </span>
                    )}
                  </td>
                  <td style={td}>
                    <span style={{ fontSize: 12, color: "#1a1a18" }}>
                      {isRunning ? "—" : `${scan.metrics.total_violations}건`}
                    </span>
                  </td>
                  <td style={td}>
                    <span style={{ fontSize: 12, color: "#1a1a18" }}>
                      {isRunning ? "—" : `${scan.metrics.critical_high}건`}
                    </span>
                  </td>
                  <td style={td}>
                    <span style={{ fontSize: 12, color: "#1a1a18" }}>
                      {isRunning ? "—" : `${scan.metrics.patch_rate}%`}
                    </span>
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
                    ) : isRunning ? (
                      <span style={{ fontSize: 10, color: "#E8A838" }}>대기 중</span>
                    ) : (
                      <button onClick={() => onSelectScan(scan.scan_id)} style={ghostBtn}>
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
