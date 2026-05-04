import { scanList, scanDetails } from "../data/dummyData";

// 백엔드 연동 시 아래 두 함수의 구현만 교체하면 됩니다.
// export const fetchScanList    = () => fetch("/api/scans").then((r) => r.json());
// export const fetchScanDetails = (id) => fetch(`/api/scans/${id}/details`).then((r) => r.json());

export const fetchScanList = () => Promise.resolve(scanList);

export const fetchScanDetails = (scanId) => Promise.resolve(scanDetails[scanId] ?? null);
