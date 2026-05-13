import axios from "axios";
import sampleHealth from "../../purpleteam-gcp-sync-20260511T022501Z/api-samples/api-health.json";
import sampleScanDetail from "../mock/api-scan-detail-ai-run-20260511-092330.json";
import sampleScans from "../mock/api-scans.json";
import { adaptScanDetail, adaptScanList } from "./aiPackAdapter";

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "";
export const AI_PACK_API_BASE_URL = import.meta.env.VITE_AI_PACK_API_BASE_URL || "";
export const ACTIVE_API_BASE_URL = API_BASE_URL || "";

export const USE_MOCK = !ACTIVE_API_BASE_URL;

const mockScans = adaptScanList(sampleScans);
const mockDetails = Object.fromEntries(mockScans.map((scan) => [
  scan.scan_id,
  scan.scan_id === "ai-run-20260511-092330"
    ? sampleScanDetail
    : { ...sampleScanDetail, scan_id: scan.scan_id, scanned_at: scan.scanned_at, status: scan.status, summary: scan },
]));

const api = axios.create({
  baseURL: ACTIVE_API_BASE_URL || "/api",
  timeout: 30000,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("auth_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export async function fetchHealth() {
  if (USE_MOCK) {
    return {
      ...sampleHealth,
      status: "mock",
      source: "purpleteam_backend_fixture",
      message: "Set VITE_API_BASE_URL to connect the PurpleTeam backend API.",
    };
  }
  const response = await api.get("/health");
  return response.data;
}

export async function fetchScanList() {
  if (USE_MOCK) return mockScans;
  const response = await api.get("/scans");
  return adaptScanList(response.data);
}

export async function fetchScanDetails(scanId, scanContext = null) {
  const scan = scanContext ?? mockScans.find((item) => item.scan_id === scanId);
  if (USE_MOCK) return adaptScanDetail(mockDetails[scanId] ?? sampleScanDetail, { scanId, scan });
  const response = await api.get(`/scans/${scanId}/details`);
  return adaptScanDetail(response.data, { scanId });
}

export async function fetchScanStatus() {
  if (USE_MOCK) return { running: false, status: "completed", scan_id: mockScans[0]?.scan_id ?? null };
  const response = await api.get("/scans/start/status");
  return response.data;
}

export async function startScan() {
  if (USE_MOCK) return { scan_id: null, status: "mock" };
  const response = await api.post("/scans/start");
  return response.data;
}

export async function savePentestResult(scanId, result) {
  const payload = {
    ...result,
    target_assets: normalizeTargetAssets(result.target_assets),
  };
  if (USE_MOCK) return { status: "ok", db_saved: true, result: payload };
  const response = await api.post(`/scans/${scanId}/pentest`, payload);
  if (response.data?.db_saved === false) {
    throw new Error("Pentest result was not saved to DB.");
  }
  return response.data;
}

export async function deletePentestResult(scanId, testId) {
  if (USE_MOCK) return { status: "ok", db_deleted: true, test_id: testId };
  const response = await api.delete(`/scans/${scanId}/pentest/${encodeURIComponent(testId)}`);
  if (response.data?.status !== "ok") {
    throw new Error("Pentest result was not deleted.");
  }
  return response.data;
}

export async function fetchEvidenceByIds(ids) {
  if (!ids?.length) return [];
  if (USE_MOCK) return [];
  const response = await api.post("/evidence/batch", { ids });
  return response.data;
}

export async function fetchInvariants() {
  if (USE_MOCK) {
    const details = await fetchScanDetails(mockScans[0]?.scan_id);
    return details?.invariants ?? [];
  }
  const response = await api.get("/invariants");
  return response.data;
}

export async function createInvariant(definition) {
  const payload = {
    ...definition,
    id: definition.id ?? definition.invariant_id,
    description: definition.description ?? definition.title ?? "",
    invariant_source: definition.invariant_source ?? definition.source ?? "custom",
    severity: definition.severity ?? "Medium",
    attack_phase: definition.attack_phase ?? "",
    category: definition.category ?? "",
    default_zone: definition.default_zone ?? "",
    weight: definition.weight ?? 1,
    remediation: definition.remediation ?? "",
  };
  if (USE_MOCK) return { status: "ok", id: payload.id };
  const response = await api.post("/invariants", payload);
  return response.data;
}

function normalizeTargetAssets(value = []) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => {
    if (typeof item === "string") return { asset_id: item, asset_type: "unknown" };
    return {
      asset_id: item.asset_id ?? item.id,
      asset_type: item.asset_type ?? item.type ?? "unknown",
    };
  }).filter((item) => item.asset_id);
}
