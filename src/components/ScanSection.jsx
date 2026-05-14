import { EmptyRow, SectionTitle } from "./common";

export default function ScanSection({ scanList = [], selectedScanId, onSelectScan, onRefresh }) {
  return (
    <section>
      <SectionTitle title="점검 관리" subtitle="완료된 ai-run snapshot을 기준으로 대시보드 데이터를 조회합니다." />
      <div style={styles.actions}>
        <button style={styles.secondaryButton} onClick={() => onRefresh?.()}>점검 목록 새로고침</button>
        <span style={styles.status}>신규 scan 시작 API는 현재 백엔드 기준 미연결 상태라 호출하지 않습니다.</span>
      </div>
      <div style={styles.card}>
        <table style={styles.table}>
          <thead>
            <tr>{["Scan ID", "점검 시간", "상태", "자산", "서비스", "위반", "체인", "출처"].map((head) => <th key={head} style={styles.th}>{head}</th>)}</tr>
          </thead>
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
            {!scanList.length && <EmptyRow colSpan={8} text="점검 이력이 없습니다." />}
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
  secondaryButton: { border: "1px solid #d0d5dd", background: "#fff", color: "#344054", borderRadius: 7, padding: "8px 12px", fontWeight: 700, cursor: "pointer" },
  status: { fontSize: 12, color: "#667085" },
};
