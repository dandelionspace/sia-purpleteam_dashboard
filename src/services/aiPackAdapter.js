const EMPTY_DETAIL = {
  scan_id: null,
  scanned_at: null,
  status: "unknown",
  summary: {},
  assets: [],
  assetChanges: [],
  assetReviewQueue: [],
  invariantImpact: [],
  violations: [],
  invariantReadiness: [],
  ai1EvaluationTrace: [],
  ai1LlmReviews: [],
  attackChains: [],
  ai2ChainReports: [],
  mitreTacticMap: {},
  securityPostureTimeline: { points: [] },
  pentestResults: [],
  ai3ReportInput: {},
  ai3ReportMakerDbExport: {},
  invariants: [],
  adapterStatus: "ok",
  adapterErrors: [],
};

const SENSITIVE_KEY = /(token|secret|password|private[_-]?key|credential|authorization|cookie)/i;

function arr(value) {
  if (Array.isArray(value)) return value;
  if (value && Array.isArray(value.items)) return value.items;
  if (value && Array.isArray(value.results)) return value.results;
  return [];
}

function obj(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function first(...values) {
  return values.find((value) => value !== undefined && value !== null);
}

function compact(values) {
  return arr(values).filter((value) => value !== undefined && value !== null && value !== "");
}

function countUnique(values) {
  return new Set(compact(values)).size;
}

function firstCount(...values) {
  return values.find((value) => typeof value === "number" && value > 0) ?? 0;
}

function chainStepText(step) {
  if (!step) return "";
  if (typeof step === "string") return step;
  return first(step.step, step.finding, step.location, step.path, step.title, step.reason, "");
}

function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      SENSITIVE_KEY.test(key) ? "[redacted]" : redact(item),
    ])
  );
}

export function adaptScanList(payload) {
  const source = Array.isArray(payload) ? payload : arr(payload?.scans ?? payload?.runs ?? payload);
  return source.map((scan) => {
    const metrics = obj(scan.metrics ?? scan.summary);
    return {
      ...scan,
      scan_id: first(scan.scan_id, scan.run_id, scan.id),
      snapshot_id: scan.snapshot_id,
      scanned_at: first(scan.scanned_at, scan.created_at, scan.completed_at),
      status: scan.status ?? "unknown",
      asset_count: first(scan.asset_count, metrics.asset_count, 0),
      service_count: first(scan.service_count, metrics.service_count, 0),
      total_violations: first(scan.total_violations, scan.violated_invariant_count, metrics.violated_invariant_count, 0),
      attack_chains_count: first(scan.attack_chains_count, scan.ai2_chain_scenario_count, metrics.ai2_chain_scenario_count, 0),
      source: scan.source ?? "ai_pack",
    };
  });
}

function adaptEvidence(evidence) {
  const safe = redact(evidence);
  const producer = obj(safe.producer);
  const target = obj(safe.target);
  const access = obj(safe.access);
  return {
    ...safe,
    evidence_id: safe.evidence_id ?? safe.id,
    evidence_type: safe.evidence_type ?? safe.source?.event_type ?? safe.raw_ref?.source_event_type ?? "unknown",
    asset_id: first(safe.asset?.asset_id, safe.asset_id, target.asset_id, producer.asset_id, safe.producer_asset_id, safe.target_asset_id),
    producer_asset_id: first(producer.asset_id, safe.producer_asset_id),
    target_asset_id: first(target.asset_id, safe.target_asset_id),
    collected_at: safe.collected_at ?? safe.timestamp ?? safe.created_at,
    security_context: obj(safe.security_context ?? {
      trace_id: safe.trace_id,
      request_id: safe.request_id,
    }),
    observed: obj(safe.observed),
    access: {
      ...access,
      method: first(access.method, safe.access_method),
      endpoint: first(access.endpoint, safe.access_endpoint),
      action: first(access.action, safe.access_action),
      decision: first(access.decision, access.authorization_decision, safe.access_decision),
      authorization_decision: first(access.authorization_decision, access.decision, safe.access_decision),
      status_code: first(access.status_code, safe.access_status_code),
    },
  };
}

function adaptViolation(violation, traceByInvariant) {
  const invariantId = first(violation.invariant_id, violation.id);
  return {
    ...violation,
    id: violation.id ?? violation.result_id ?? invariantId,
    result_id: violation.result_id ?? violation.id,
    invariant_id: invariantId,
    status: violation.status ?? "violated",
    severity: normalizeSeverity(violation.severity),
    confidence: typeof violation.confidence === "number" ? violation.confidence : null,
    evidence_ids: arr(first(violation.evidence_ids, violation.evidence_refs, violation.matched_evidence_ids)),
    asset_ids: arr(first(violation.asset_ids, violation.affected_registry_asset_ids, violation.affected_asset_ids)),
    affected_registry_asset_ids: arr(violation.affected_registry_asset_ids),
    affected_services: arr(violation.affected_services),
    affected_zones: arr(violation.affected_zones),
    ai1_trace: traceByInvariant[invariantId] ?? null,
  };
}

function normalizeSeverity(value = "medium") {
  const lower = String(value).toLowerCase();
  if (lower === "critical") return "Critical";
  if (lower === "high") return "High";
  if (lower === "low") return "Low";
  return "Medium";
}

function adaptChainReport(report) {
  const rawSteps = arr(report.step_reports ?? report.steps);
  const flowSteps = arr(report.mitre_attack_flow);
  const fallbackStepIds = rawSteps.length || flowSteps.length ? [] : arr(report.attack_chain);
  const stepSource = rawSteps.length
    ? rawSteps
    : flowSteps.length
      ? flowSteps.map((flow) => ({
        ...flow,
        location: first(flow.tactic_name, flow.tactic),
        path: first(flow.technique_name, flow.technique),
        finding: flow.step,
        chain_transition: flow.reason,
      }))
      : fallbackStepIds.map((stepText, index) => ({
        step_id: stepText,
        order: index + 1,
        location: `Step ${index + 1}`,
        path: "",
        finding: stepText,
      }));
  const steps = stepSource.map((step, index) => ({
    ...step,
    order: step.order ?? step.step_order ?? index + 1,
    location: first(step.location, step.title, step.category, step.vm, "Evidence correlation step"),
    path: first(step.path, step.endpoint, step.step_id),
    finding: first(step.finding, step.step, step.summary, step.description),
    chain_transition: first(step.chain_transition, step.transition_to_next, step.reason),
    related_invariants: arr(first(step.related_invariants, step.violation_ids, step.violated_invariants)),
    evidence_ids: arr(first(step.evidence_ids, step.evidence_refs, step.matched_evidence_ids)),
    threatened_asset_ids: arr(first(step.threatened_asset_ids, step.affected_asset_ids, step.asset_ids, step.target_asset_ids)),
    redteam_focus: arr(step.redteam_focus ?? step.validation_focus),
  }));
  const rawAttackChain = arr(report.attack_chain).map(chainStepText).filter(Boolean);
  return {
    ...report,
    chain_scenario_id: first(report.chain_scenario_id, report.scenario_id, report.id),
    risk_level: report.risk_level ?? "medium",
    related_invariants: arr(report.related_invariants),
    step_reports: steps,
    attack_chain: rawAttackChain.length
      ? rawAttackChain
      : steps.map((step) => chainStepText(step)).filter(Boolean),
  };
}

function chainScenarioId(chain) {
  return first(chain?.chain_scenario_id, chain?.scenario_id, chain?.id);
}

function mergeChainSources(primaryChains, secondaryChains) {
  const merged = new Map();

  arr(secondaryChains).forEach((chain) => {
    const id = chainScenarioId(chain);
    if (id) merged.set(id, chain);
  });

  arr(primaryChains).forEach((chain) => {
    const id = chainScenarioId(chain);
    if (!id) return;
    const existing = obj(merged.get(id));
    merged.set(id, {
      ...existing,
      ...chain,
      attack_chain: arr(chain.attack_chain).length ? chain.attack_chain : existing.attack_chain,
      mitre_attack_flow: arr(chain.mitre_attack_flow).length ? chain.mitre_attack_flow : existing.mitre_attack_flow,
      step_reports: arr(chain.step_reports ?? chain.steps).length
        ? first(chain.step_reports, chain.steps)
        : first(existing.step_reports, existing.steps),
      related_invariants: arr(chain.related_invariants).length ? chain.related_invariants : existing.related_invariants,
    });
  });

  return [...merged.values()];
}

function adaptMitreMap(payload) {
  if (Array.isArray(payload)) {
    return {
      tactics: payload.map((item) => ({
        ...item,
        violated_invariants: arr(item.violated_invariants ?? item.invariants),
        evidence_summaries: arr(item.evidence_summaries),
        affected_asset_ids: arr(item.affected_asset_ids),
        next_possible_invariants: arr(item.next_possible_invariants),
        chain_candidate_ids: arr(item.chain_candidate_ids),
      })),
    };
  }
  const map = obj(payload);
  const tactics = arr(map.tactics ?? map.active_tactics ?? map.items);
  if (tactics.length) return { ...map, tactics };
  return { ...map, tactics: Object.entries(map).filter(([, v]) => typeof v === "object").map(([id, value]) => ({ tactic_id: id, ...value })) };
}

function adaptPentest(result) {
  const scenarioId = first(result.chain_scenario_id, result.scenario_id);
  return {
    ...result,
    test_id: first(result.test_id, result.validation_id, result.id),
    scenario_id: scenarioId,
    chain_scenario_id: scenarioId,
    tester: first(result.tester, result.validated_by),
    tested_at: first(result.tested_at, result.created_at),
    overall_verdict: normalizeVerdict(first(result.overall_verdict, result.validation_status)),
    related_invariants: arr(result.related_invariants),
    target_assets: arr(first(result.target_assets, result.affected_asset_ids)),
    narrative: obj(result.narrative),
  };
}

function normalizeVerdict(value) {
  const map = {
    confirmed: "reproduced",
    partially_reproduced: "partially_reproduced",
    rejected: "not_reproduced",
    needs_more_evidence: "in_progress",
  };
  return map[value] ?? value ?? "in_progress";
}

function adaptAsset(asset) {
  return {
    ...asset,
    id: first(asset.id, asset.asset_id),
    asset_id: first(asset.asset_id, asset.id),
    asset_name: first(asset.asset_name, asset.name, asset.asset_id, asset.id),
    asset_type: first(asset.asset_type, asset.type, "unknown"),
    related_invariant_ids: arr(first(asset.related_invariant_ids, asset.violation_ids, asset.invariant_ids)),
    evidence_ids: arr(asset.evidence_ids),
  };
}

function adaptInvariant(invariant) {
  const id = first(invariant.invariant_id, invariant.id);
  const rawTitle = first(invariant.title, invariant.name, invariant.catalog_title);
  const descriptionIsId = invariant.description === id;
  return {
    ...invariant,
    id,
    invariant_id: id,
    title: rawTitle && rawTitle !== id ? rawTitle : (!descriptionIsId ? invariant.description : null),
    source: first(invariant.source, invariant.invariant_source, "fixed"),
    state: first(invariant.state, invariant.active === false ? "disabled" : "active"),
    approval_status: first(invariant.approval_status, invariant.catalog_status, invariant.approval_state, "approved"),
    evaluation_status: first(invariant.evaluation_status, invariant.status),
  };
}

function buildSummary(rawSummary, timeline, assets, services, violations, chains, invariants = [], scan = {}) {
  const latestMetrics = obj(arr(timeline.points).at(-1)?.metrics);
  const summary = obj(rawSummary);
  const inferredInvariantTotal = firstCount(
    arr(invariants).length,
    countUnique(violations.map((violation) => violation.invariant_id ?? violation.id))
  );
  return {
    ...latestMetrics,
    ...summary,
    asset_count: first(summary.asset_count, scan.asset_count, latestMetrics.asset_count, assets.length, 0),
    service_count: first(summary.service_count, scan.service_count, latestMetrics.service_count, services.length, 0),
    invariant_total: firstCount(summary.invariant_total, latestMetrics.invariant_total, inferredInvariantTotal),
    violated_invariant_count: first(summary.violated_invariant_count, summary.total_violations, latestMetrics.violated_invariant_count, violations.length, 0),
    applied_invariant_count: first(summary.applied_invariant_count, latestMetrics.applied_invariant_count, 0),
    ai2_chain_scenario_count: first(summary.ai2_chain_scenario_count, summary.attack_chains, latestMetrics.ai2_chain_scenario_count, chains.length, 0),
    changed_asset_count: first(summary.changed_asset_count, latestMetrics.changed_asset_count, 0),
    new_asset_count: first(summary.new_asset_count, latestMetrics.new_asset_count, 0),
    missing_asset_observation_count: first(summary.missing_asset_observation_count, latestMetrics.missing_asset_observation_count, 0),
  };
}

function buildTimeline(raw, summary, scanId, scannedAt) {
  const explicit = obj(raw.securityPostureTimeline ?? raw.security_posture_timeline);
  const points = arr(explicit.points);
  if (points.length) return { ...explicit, points };
  return {
    points: [{
      run_id: first(raw.run_id, scanId),
      created_at: scannedAt,
      metrics: {
        asset_count: summary.asset_count ?? 0,
        service_count: summary.service_count ?? 0,
        invariant_total: summary.invariant_total ?? 0,
        violated_invariant_count: summary.violated_invariant_count ?? 0,
        applied_invariant_count: summary.applied_invariant_count ?? 0,
        changed_asset_count: summary.changed_asset_count ?? 0,
        ai2_chain_scenario_count: summary.ai2_chain_scenario_count ?? 0,
      },
      changed_assets: [],
      violated_invariants: [],
      new_violations_since_previous_run: compact(summary.new_violations_since_previous_run),
      resolved_invariants_since_previous_run: compact(summary.resolved_invariants_since_previous_run),
    }],
  };
}

export function adaptScanDetail(payload, context = {}) {
  const raw = obj(payload);
  const trace = arr(raw.ai1EvaluationTrace ?? raw.ai1_evaluation_trace);
  const traceByInvariant = Object.fromEntries(trace.map((item) => [item.invariant_id, item]));
  const ai2Reports = arr(raw.ai2ChainReports?.reports ?? raw.ai2_chain_reports?.reports ?? raw.ai2ChainReports ?? raw.ai2_chain_reports);
  const dbChains = arr(raw.attackChains ?? raw.attack_chains);
  const chainSource = mergeChainSources(ai2Reports, dbChains);
  const chains = chainSource.map(adaptChainReport);
  const violations = arr(raw.violations ?? raw.invariant_results).map((item) => adaptViolation(item, traceByInvariant));
  const invariants = arr(raw.invariants ?? raw.invariant_catalog).map(adaptInvariant);
  const assets = arr(raw.assets).map(adaptAsset);
  const services = arr(raw.services);
  const evidenceEvents = arr(raw.evidenceEvents ?? raw.evidence_events ?? raw.evidence).map(adaptEvidence);
  const scan_id = first(raw.scan_id, raw.run_id, raw.id, context.scanId, context.scan?.scan_id);
  const scanned_at = first(raw.scanned_at, raw.created_at, raw.completed_at, context.scan?.scanned_at);
  const baseSummary = buildSummary(raw.summary, obj(raw.securityPostureTimeline ?? raw.security_posture_timeline), assets, services, violations, chains, invariants, context.scan);
  const timeline = buildTimeline(raw, baseSummary, scan_id, scanned_at);
  const summary = buildSummary(baseSummary, timeline, assets, services, violations, chains, invariants, context.scan);

  return {
    ...EMPTY_DETAIL,
    ...raw,
    scan_id,
    scanned_at,
    status: first(raw.status, context.scan?.status, "unknown"),
    summary,
    assets,
    services,
    assetChanges: arr(raw.assetChanges ?? raw.asset_changes),
    assetReviewQueue: arr(raw.assetReviewQueue ?? raw.asset_review_queue),
    invariantImpact: arr(raw.invariantImpact ?? raw.assetInvariantImpact ?? raw.asset_invariant_impact ?? raw.invariant_impact),
    violations,
    invariantReadiness: arr(raw.invariantReadiness ?? raw.invariant_readiness),
    ai1EvaluationTrace: trace,
    ai1LlmReviews: arr(raw.ai1LlmReviews ?? raw.ai1_llm_reviews),
    attackChains: chains,
    ai2ChainReports: chains,
    mitreTacticMap: adaptMitreMap(raw.mitreTacticMap ?? raw.mitre_tactic_map ?? raw.mitreMapping ?? raw.mitre_mapping),
    securityPostureTimeline: timeline,
    pentestResults: arr(raw.pentestResults ?? raw.pentest_results ?? raw.redteam_validation).map(adaptPentest),
    ai3ReportInput: obj(raw.ai3ReportInput ?? raw.ai3_report_input),
    ai3ReportMakerDbExport: obj(raw.ai3ReportMakerDbExport ?? raw.ai3_report_maker_db_export),
    invariants,
    evidenceEvents,
    adapterStatus: "ok",
    adapterErrors: [],
  };
}
