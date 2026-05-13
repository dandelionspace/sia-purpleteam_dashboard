const NORMAL_STATUSES = new Set([
  "applied",
  "normal",
  "ok",
  "passed",
  "pass",
  "not_violated",
  "no_violation",
  "not_observed",
  "no_violation_observed",
]);

export function classifyInvariantJudgment(item = {}) {
  const status = normalize(item.evaluation_status ?? item.status ?? item.last_result_status);
  const reason = normalize(item.violation_reason ?? item.last_violation_reason ?? item.reason);
  const testable = item.current_environment_testable;

  if (status === "violated" && reason === "clear_violation") {
    return "confirmedViolation";
  }

  if (
    testable === false ||
    ["unknown", "inconclusive", "unverified", "not_testable"].includes(status)
  ) {
    return "unverifiable";
  }

  if (status === "violated" || reason) {
    return "confirmedViolation";
  }

  if (NORMAL_STATUSES.has(status) || !status) {
    return "normalOrNotObserved";
  }

  return "unverifiable";
}

export function buildInvariantJudgmentCounts(invariants = [], violations = []) {
  const byId = new Map();

  invariants.forEach((item) => {
    const id = invariantId(item);
    if (id) byId.set(id, item);
  });

  violations.forEach((item) => {
    const id = invariantId(item);
    if (!id) return;
    byId.set(id, { ...(byId.get(id) ?? {}), ...item });
  });

  const counts = {
    confirmedViolation: 0,
    unverifiable: 0,
    normalOrNotObserved: 0,
  };

  byId.forEach((item) => {
    counts[classifyInvariantJudgment(item)] += 1;
  });

  return counts;
}

function invariantId(item = {}) {
  return item.invariant_id ?? item.id;
}

function normalize(value) {
  return String(value ?? "").trim().toLowerCase();
}
