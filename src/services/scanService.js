import axios from "axios";
import sampleHealth from "../../latest_ai_response_ai-run-20260513-131059/api/health.json";
import sampleScanDetail from "../../latest_ai_response_ai-run-20260513-131059/api/scan_details.json";
import sampleScans from "../../latest_ai_response_ai-run-20260513-131059/api/scans.json";
import { adaptScanDetail, adaptScanList } from "./aiPackAdapter";

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "";
export const AI_PACK_API_BASE_URL = import.meta.env.VITE_AI_PACK_API_BASE_URL || "";
export const ACTIVE_API_BASE_URL = API_BASE_URL || "";
export const BASELINE_SCAN_ID = "ai-run-20260513-131059";

export const USE_MOCK = !ACTIVE_API_BASE_URL;

const mockScans = adaptScanList(sampleScans);
const sampleScanId = sampleScanDetail.scan_id ?? sampleScanDetail.run_id ?? BASELINE_SCAN_ID;
const mockDetails = Object.fromEntries(mockScans.map((scan) => [
  scan.scan_id,
  scan.scan_id === sampleScanId
    ? { ...sampleScanDetail, scan_id: sampleScanId, scanned_at: scan.scanned_at, status: scan.status }
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
  if (USE_MOCK) return sortScansForDashboard(mockScans);
  const response = await api.get("/scans");
  return sortScansForDashboard(adaptScanList(response.data));
}

export async function fetchScanDetails(scanId, scanContext = null) {
  if (!scanId) throw new Error("scan_id is required to fetch scan details.");
  const scan = scanContext ?? mockScans.find((item) => item.scan_id === scanId);
  if (USE_MOCK) return adaptScanDetail(mockDetails[scanId] ?? sampleScanDetail, { scanId, scan });
  const response = await api.get(`/scans/${scanId}/details`);
  return adaptScanDetail(response.data, { scanId });
}

export async function fetchScanStatus() {
  if (USE_MOCK) return { running: false, status: "completed", scan_id: mockScans[0]?.scan_id ?? null };
  return { running: false, status: "disabled", message: "Scan start/status API is not available in the current GCP backend." };
}

export async function startScan() {
  if (USE_MOCK) return { scan_id: null, status: "mock" };
  throw new Error("Scan start API is disabled. Use completed ai-run-* snapshots from GET /api/scans.");
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

export function isCompletedAiRun(scan) {
  const scanId = String(scan?.scan_id ?? scan?.scanId ?? "");
  const status = scan?.status ?? scan?.scan_status;
  return scanId.startsWith("ai-run-") && status === "completed";
}

export function sortScansForDashboard(scans = []) {
  return [...scans].sort((a, b) => {
    const aiRunDelta = Number(isCompletedAiRun(b)) - Number(isCompletedAiRun(a));
    if (aiRunDelta) return aiRunDelta;
    return new Date(b.scanned_at ?? b.created_at ?? 0) - new Date(a.scanned_at ?? a.created_at ?? 0);
  });
}
