import { useState } from "react";
import { fetchScanStatus, startScan } from "../services/scanService";
import { EmptyRow, SectionTitle } from "./common";

export default function ScanSection({ scanList = [], selectedScanId, onSelectScan, onRefresh, onTriggerComplete }) {
  const [scanState, setScanState] = useState(null);

  const handleStart = async () => {
    setScanState({ status: "checking", message: "점검 상태 확인 중..." });
    try {
      const statusResult = await fetchScanStatus();
      if (statusResult?.running) {
        setScanState({
          status: "running",
          message: `점검 진행 중 — ${statusResult.elapsed_seconds != null ? `${statusResult.elapsed_seconds}초 경과` : ""} ${statusResult.snapshot_size_bytes != null ? `/ 스냅샷 ${(statusResult.snapshot_size_bytes / 1024 / 1024).toFixed(1)} MB` : ""}`.trim(),
        });
        return;
      }
      setScanState({ status: "starting", message: "새 점검 시작 중..." });
      const result = await startScan();
      setScanState({ status: result.status ?? "submitted", message: result.scan_id ? `scan_id: ${result.scan_id}` : "점검이 시작되었습니다." });
      await onTriggerComplete?.();
    } catch (error) {
      setScanState({ status: "failed", message: error.message });
    }
  };

  const isRunning = scanState?.status === "running" || scanState?.status === "starting" || scanState?.status === "checking";

  return (
    <section>
      <SectionTitle title="점검 관리" subtitle="점검(scan) 이력 관리" />
      <div style={styles.actions}>
        <button style={isRunning ? { ...styles.primaryButton, opacity: 0.5, cursor: "not-allowed" } : styles.primaryButton} onClick={handleStart} disabled={isRunning}>
          {isRunning ? "점검 진행 중..." : "새 점검 시작"}
        </button>
        <button style={styles.secondaryButton} onClick={() => onRefresh?.()}>점검 목록 새로 고침</button>
        {scanState && <span style={styles.status}>[{scanState.status}] {scanState.message}</span>}
      </div>
      <div style={styles.card}>
        <table style={styles.table}>
          <thead><tr>{["Scan ID", "점검 시간", "점검 상태", "자산 수", "Services 수", "위반 항목 수", "시나리오 수", "점검 데이터 출처"].map((head) => <th key={head} style={styles.th}>{head}</th>)}</tr></thead>
          <tbody>
            {scanList.map((scan) => (
              <tr key={scan.scan_id} onClick={() => onSelectScan?.(scan.scan_id)} style={{ cursor: "pointer", background: scan.scan_id === selectedScanId ? "#eff5ff" : "#fff" }}>
                <td style={styles.tdMono}>{scan.scan_id}</td>
                <td style={styles.td}>{formatDate(scan.scanned_at)}</td>
                <td style={styles.td}>{scan.status}</td>
                <td style={styles.td}>{scan.asset_count}</td>
                <td style={styles.td}>{scan.service_count}</td>
                <td style={styles.td}>{scan.total_violations}</td>
                <td style={styles.td}>{scan.attack_chains_count}</td>
                <td style={styles.td}>{scan.source}</td>
              </tr>
            ))}
            {!scanList.length && <EmptyRow colSpan={8} text="점검 이력이 없습니다" />}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ko-KR");
}

const styles = {
  actions: { display: "flex", alignItems: "center", gap: 8, marginBottom: 12, flexWrap: "wrap" },
  card: { background: "#fff", border: "1px solid #e4e7ec", borderRadius: 8, overflow: "hidden" },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 12 },
  th: { textAlign: "left", padding: "10px 12px", color: "#667085", borderBottom: "1px solid #e4e7ec" },
  td: { padding: "10px 12px", borderBottom: "1px solid #eef2f6", color: "#344054" },
  tdMono: { padding: "10px 12px", borderBottom: "1px solid #eef2f6", color: "#173b70", fontFamily: "monospace", fontWeight: 700 },
  primaryButton: { border: "none", background: "#2f6fed", color: "#fff", borderRadius: 7, padding: "8px 12px", fontWeight: 700, cursor: "pointer" },
  secondaryButton: { border: "1px solid #d0d5dd", background: "#fff", color: "#344054", borderRadius: 7, padding: "8px 12px", fontWeight: 700, cursor: "pointer" },
  status: { fontSize: 12, color: "#667085" },
};
