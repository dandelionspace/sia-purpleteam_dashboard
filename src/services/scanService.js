import axios from "axios";
import { scanList as mockScanList, scanDetails as mockScanDetails } from "../data/dummyData";

// VITE_API_BASE_URL이 설정되지 않으면 mock 데이터를 사용합니다.
export const USE_MOCK = !import.meta.env.VITE_API_BASE_URL;

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? "/api",
  timeout: 30000,
  headers: { "Content-Type": "application/json" },
});

// 인증 토큰 자동 첨부 — localStorage에 "auth_token"이 있을 경우 Authorization 헤더에 추가
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("auth_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export const fetchScanList = () => {
  if (USE_MOCK) return Promise.resolve(mockScanList);
  return api.get("/scans").then((r) => r.data);
};

export const fetchScanDetails = (scanId) => {
  if (USE_MOCK) return Promise.resolve(mockScanDetails[scanId] ?? null);
  return api.get(`/scans/${scanId}/details`).then((r) => r.data);
};

// 새 스캔 트리거 — 백엔드가 즉시 scan_id를 반환하고 백그라운드에서 실행
export const triggerScan = () => {
  if (USE_MOCK) return Promise.resolve({ scan_id: null, status: "mock" });
  return api.post("/scans/trigger").then((r) => r.data);
};

// Red Team 결과 저장 — test_id 기준으로 upsert
export const savePentestResult = (scanId, result) => {
  if (USE_MOCK) return Promise.resolve({ status: "ok" });
  return api.post(`/scans/${scanId}/pentest`, result).then((r) => r.data);
};
