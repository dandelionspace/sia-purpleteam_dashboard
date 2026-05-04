import axios from "axios";
import { scanList as mockScanList, scanDetails as mockScanDetails } from "../data/dummyData";

// VITE_API_BASE_URL이 설정되지 않으면 mock 데이터를 사용합니다.
const USE_MOCK = !import.meta.env.VITE_API_BASE_URL;

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
