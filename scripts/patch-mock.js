const fs = require('fs');
const path = require('path');

const BASE = 'C:/Users/user/Desktop/securityAcademy/argus-dashboard';
const srcDir = path.join(BASE, 'purpleteam-gcp-sync-20260511T022501Z/api-samples');
const outDir = path.join(BASE, 'src/mock');
fs.mkdirSync(outDir, { recursive: true });

console.log('Reading source detail file...');
const d = JSON.parse(fs.readFileSync(path.join(srcDir, 'api-scan-detail-ai-run-20260511-010650.json'), 'utf8'));
console.log('Read complete. violations:', d.violations?.length, 'invariants:', d.invariants?.length);

const NEW_SCAN_ID = 'ai-run-20260511-092330';

// 카테고리 분류: invariant_id 패턴에서 추출, 없으면 round-robin
const CATEGORIES = ['ACC', 'CRED', 'AUD', 'ACC', 'ACC', 'CRED', 'AUD', 'AUD', 'ACC', 'CRED', 'AUD', 'ACC'];
const EVIDENCE_TYPE_BY_CAT = { CRED: 'key_management_state', AUD: 'log_trace_state', ACC: 'privileged_access_event' };
const SOURCE_REF_BY_CAT   = { CRED: '/etc/argos/ops/key_registry.json', AUD: '/var/log/argos/audit.log', ACC: '/etc/argos/ops/privileged_access_policy.json' };
const TACTIC_BY_CAT       = { CRED: { tactic: 'TA0006', name: 'Credential Access' }, AUD: { tactic: 'TA0005', name: 'Defense Evasion' }, ACC: { tactic: 'TA0004', name: 'Privilege Escalation' } };

function deriveCategory(v, index) {
  if (v.type && ['ACC','CRED','AUD'].includes(v.type.toUpperCase())) return v.type.toUpperCase();
  if (v.category && ['ACC','CRED','AUD'].includes(v.category.toUpperCase())) return v.category.toUpperCase();
  // invariant_id에서 추출: INV-ARG-ACC-01 → ACC
  const parts = (v.invariant_id || '').split('-');
  for (const p of parts) {
    if (['ACC','CRED','AUD'].includes(p)) return p;
  }
  return CATEGORIES[index % CATEGORIES.length];
}

// 1. violations 패치
const patchedViolations = (d.violations || []).map((v, i) => {
  const cat = deriveCategory(v, i);
  const evType = EVIDENCE_TYPE_BY_CAT[cat];
  const srcRef = SOURCE_REF_BY_CAT[cat];
  return {
    ...v,
    scan_id: NEW_SCAN_ID,
    type: v.type || cat,
    category: v.category || cat,
    judgment_summary: v.judgment_summary || v.summary || null,
    missing_evidence_fields: v.missing_evidence_fields || [],
    affected_assets: v.affected_assets || [],
    affected_resources: v.affected_resources || [],
    affected_services: v.affected_services || [],
    evidence_details: (v.evidence_details && v.evidence_details.length > 0) ? v.evidence_details : [
      {
        evidence_id: 'evd-mock-' + String(i).padStart(4, '0') + 'a',
        timestamp: '2026-05-11T05:51:45.066048+00:00',
        evidence_type: evType,
        trace_id: 'state-scan-20260511054839',
        request_id: 'state-scan-20260511054839',
        producer_vm: 'argos-ops',
        producer_component_id: 'argos-ops-policy-collector',
        producer_component_type: null,
        producer_zone: 'ops',
        observed: {
          scan_id: NEW_SCAN_ID,
          summary: evType + ' | argos-ops',
          event_type: evType,
          source_ref: srcRef,
          related_invariant_ids: [v.invariant_id]
        },
        raw_ref: { source: srcRef, agent: null, location: null, log_id: null },
        producer: { vm: 'argos-ops', component_id: 'argos-ops-policy-collector', component_type: null, zone: 'ops' },
        access: { action: null, endpoint: null, method: null, decision: null, status_code: null },
        target: { asset_id: null, asset_type: null }
      }
    ]
  };
});

// 2. mitreTacticMap: 계약서 기준 missing_or_insufficient_evidence
const patchedMitreTacticMap = {
  ...d.mitreTacticMap,
  mapping_status: 'missing_or_insufficient_evidence',
  active_tactic_count: 0,
  tactics: (d.mitreTacticMap?.tactics || []).map(t => ({ ...t, active: false, violation_count: 0, invariants: [] }))
};

// 3. diagnosticMitreTacticMap: 카테고리 기반 active tactics
const credIds = patchedViolations.filter(v => v.type === 'CRED').map(v => v.invariant_id);
const accIds  = patchedViolations.filter(v => v.type === 'ACC').map(v => v.invariant_id);
const audIds  = patchedViolations.filter(v => v.type === 'AUD').map(v => v.invariant_id);

const diagnosticMitreTacticMap = {
  schema_version: 'argos-dashboard-mitre-tactic-map',
  generated_at: '2026-05-11T09:35:23.077003+00:00',
  mapping_status: 'diagnostic_fallback_by_invariant_category',
  mapping_policy: {
    mitre_scope: 'enterprise_tactic_only',
    mitre_is_chain_generation_source: false,
    ui_policy: 'diagnostic_only_not_official_ai_pack_mapping'
  },
  active_tactic_count: [credIds, accIds, audIds].filter(a => a.length > 0).length,
  inactive_tactic_count: 14 - [credIds, accIds, audIds].filter(a => a.length > 0).length,
  tactics: [
    { tactic_id: 'TA0043', tactic_name: 'Reconnaissance', active: false, violation_count: 0, violated_invariants: [], invariants: [], mapping_basis: 'fallback_by_invariant_category' },
    { tactic_id: 'TA0042', tactic_name: 'Resource Development', active: false, violation_count: 0, violated_invariants: [], invariants: [], mapping_basis: 'fallback_by_invariant_category' },
    { tactic_id: 'TA0001', tactic_name: 'Initial Access', active: false, violation_count: 0, violated_invariants: [], invariants: [], mapping_basis: 'fallback_by_invariant_category' },
    { tactic_id: 'TA0002', tactic_name: 'Execution', active: false, violation_count: 0, violated_invariants: [], invariants: [], mapping_basis: 'fallback_by_invariant_category' },
    { tactic_id: 'TA0003', tactic_name: 'Persistence', active: false, violation_count: 0, violated_invariants: [], invariants: [], mapping_basis: 'fallback_by_invariant_category' },
    { tactic_id: 'TA0004', tactic_name: 'Privilege Escalation', active: accIds.length > 0, violation_count: accIds.length, violated_invariants: accIds, invariants: accIds, mapping_basis: 'fallback_by_invariant_category' },
    { tactic_id: 'TA0005', tactic_name: 'Defense Evasion', active: audIds.length > 0, violation_count: audIds.length, violated_invariants: audIds, invariants: audIds, mapping_basis: 'fallback_by_invariant_category' },
    { tactic_id: 'TA0006', tactic_name: 'Credential Access', active: credIds.length > 0, violation_count: credIds.length, violated_invariants: credIds, invariants: credIds, mapping_basis: 'fallback_by_invariant_category' },
    { tactic_id: 'TA0007', tactic_name: 'Discovery', active: false, violation_count: 0, violated_invariants: [], invariants: [], mapping_basis: 'fallback_by_invariant_category' },
    { tactic_id: 'TA0008', tactic_name: 'Lateral Movement', active: false, violation_count: 0, violated_invariants: [], invariants: [], mapping_basis: 'fallback_by_invariant_category' },
    { tactic_id: 'TA0009', tactic_name: 'Collection', active: false, violation_count: 0, violated_invariants: [], invariants: [], mapping_basis: 'fallback_by_invariant_category' },
    { tactic_id: 'TA0011', tactic_name: 'Command and Control', active: false, violation_count: 0, violated_invariants: [], invariants: [], mapping_basis: 'fallback_by_invariant_category' },
    { tactic_id: 'TA0010', tactic_name: 'Exfiltration', active: false, violation_count: 0, violated_invariants: [], invariants: [], mapping_basis: 'fallback_by_invariant_category' },
    { tactic_id: 'TA0040', tactic_name: 'Impact', active: false, violation_count: 0, violated_invariants: [], invariants: [], mapping_basis: 'fallback_by_invariant_category' }
  ]
};

// 4. diagnosticRedteamCandidates
const diagnosticRedteamCandidates = [
  {
    chain_scenario_id: 'redteam-derived-credential-to-identity-to-audit',
    created_at: '2026-05-11T09:35:23.024326+00:00',
    title: '인증정보 노출에서 권한 오용과 탐지 회피까지의 검증 체인',
    source_bundle_id: 'derived-from-ai1-violations-and-final-invariant-catalog',
    risk_level: 'high',
    derived: true,
    scenario_basis: {
      status: 'violated',
      violation_reason: 'derived_redteam_candidate',
      summary: 'AI2 원본이 하나의 evidence cluster만 반환했기 때문에, 최종 불변식 카테고리와 MITRE fallback 전술을 기준으로 레드팀 검증 후보 체인을 생성했다.'
    },
    current_environment_testable: true,
    testability_reason: 'CRED, ACC, AUD 카테고리의 위반 evidence가 존재한다. 단, 실제 공격 성공 시나리오 확정이 아니라 승인된 검증 절차를 위한 후보 체인이다.',
    attack_chain: ['redteam-derived-step-01', 'redteam-derived-step-02', 'redteam-derived-step-03'],
    chain_steps: [
      {
        order: 1, path: '인증정보 통제', location: '인증정보 통제',
        step: '인증정보 통제 영역의 위반 불변식 기준으로 승인된 테스트 계정에서 재현 가능한지 검증한다.',
        violation_point: '인증정보 통제 영역 검증',
        reason: '최종 불변식 카테고리와 MITRE fallback 전술을 기준으로 분해했다.',
        tactic: 'TA0006', tactic_name: 'Credential Access', technique: '',
        related_invariants: credIds,
        evidence_ids: patchedViolations.filter(v => v.type === 'CRED').flatMap(v => (v.evidence_ids || []).slice(0, 3)),
        evidence_count: credIds.length * 3, threatened_asset_ids: []
      },
      {
        order: 2, path: '계정/권한 통제', location: '계정/권한 통제',
        step: '계정/권한 통제 영역의 위반 불변식 기준으로 승인된 테스트 계정에서 재현 가능한지 검증한다.',
        violation_point: '계정/권한 통제 영역 검증',
        reason: '최종 불변식 카테고리와 MITRE fallback 전술을 기준으로 분해했다.',
        tactic: 'TA0004', tactic_name: 'Privilege Escalation', technique: '',
        related_invariants: accIds,
        evidence_ids: patchedViolations.filter(v => v.type === 'ACC').flatMap(v => (v.evidence_ids || []).slice(0, 3)),
        evidence_count: accIds.length * 3, threatened_asset_ids: []
      },
      {
        order: 3, path: '감사/탐지 통제', location: '감사/탐지 통제',
        step: '감사/탐지 통제 영역의 위반 불변식 기준으로 승인된 테스트 계정에서 재현 가능한지 검증한다.',
        violation_point: '감사/탐지 통제 영역 검증',
        reason: '최종 불변식 카테고리와 MITRE fallback 전술을 기준으로 분해했다.',
        tactic: 'TA0005', tactic_name: 'Defense Evasion', technique: '',
        related_invariants: audIds,
        evidence_ids: patchedViolations.filter(v => v.type === 'AUD').flatMap(v => (v.evidence_ids || []).slice(0, 3)),
        evidence_count: audIds.length * 3, threatened_asset_ids: []
      }
    ],
    related_invariants: patchedViolations.map(v => v.invariant_id),
    mitre_attack_flow: [
      { order: 1, tactic: 'TA0006', tactic_name: 'Credential Access', technique: '', step: '인증정보 통제 검증', reason: 'MITRE는 체인 정렬의 보조 전술 라벨이며 실제 검증 기준은 related_invariants다.' },
      { order: 2, tactic: 'TA0004', tactic_name: 'Privilege Escalation', technique: '', step: '계정/권한 통제 검증', reason: 'MITRE는 체인 정렬의 보조 전술 라벨이며 실제 검증 기준은 related_invariants다.' },
      { order: 3, tactic: 'TA0005', tactic_name: 'Defense Evasion', technique: '', step: '감사/탐지 통제 검증', reason: 'MITRE는 체인 정렬의 보조 전술 라벨이며 실제 검증 기준은 related_invariants다.' }
    ],
    manual_validation_guide: {
      goal: '위반 불변식 간 연결이 승인 검증 환경에서 재현 가능한지 확인한다.',
      steps: ['각 단계의 related_invariants와 evidence_ids 확인', '승인된 테스트 계정으로 순서대로 검증', '결과를 pentest 탭에 기록']
    }
  }
];

// 5. summary: scans.json 최신 값과 일치시키기
const criticalHighCount = patchedViolations.filter(v => ['Critical', 'High'].includes(v.severity)).length;
const patchedSummary = {
  total_violations: patchedViolations.length,
  violated_invariant_count: patchedViolations.length,
  applied_invariant_count: Math.max(0, (d.invariants || []).length - patchedViolations.length),
  invariant_total: (d.invariants || []).length,
  critical_high: criticalHighCount,
  attack_chains: (d.attackChains || []).length,
  ai2_chain_scenario_count: (d.attackChains || []).length,
  asset_count: (d.assets || []).length,
  service_count: (d.services || []).length
};

// 6. 최종 조합
const patched = {
  ...d,
  scan_id: NEW_SCAN_ID,
  scanned_at: '2026-05-11T09:23:44.521465+00:00',
  snapshot_id: 'asset-snapshot-20260511092343',
  status: 'completed',
  summary: patchedSummary,
  violations: patchedViolations,
  mitreTacticMap: patchedMitreTacticMap,
  diagnosticMitreTacticMap,
  diagnosticRedteamCandidates
};

const outPath = path.join(outDir, 'api-scan-detail-ai-run-20260511-092330.json');
fs.writeFileSync(outPath, JSON.stringify(patched));
const stat = fs.statSync(outPath);

console.log('\nWritten:', outPath);
console.log('  Size:', (stat.size / 1024 / 1024).toFixed(1) + ' MB');
console.log('  violations:', patched.violations.length, '(CRED:', credIds.length, '/ ACC:', accIds.length, '/ AUD:', audIds.length + ')');
console.log('  summary.critical_high:', patched.summary.critical_high);
console.log('  summary.attack_chains:', patched.summary.attack_chains);
console.log('  diagnosticRedteamCandidates:', patched.diagnosticRedteamCandidates.length);
console.log('  diagnosticMitreTacticMap.active_tactic_count:', patched.diagnosticMitreTacticMap.active_tactic_count);
console.log('  active tactics:', patched.diagnosticMitreTacticMap.tactics.filter(t => t.active).map(t => t.tactic_name).join(', '));
console.log('  mitreTacticMap.mapping_status:', patched.mitreTacticMap.mapping_status);
console.log('  violations[0].evidence_details[0].trace_id:', patched.violations[0].evidence_details?.[0]?.trace_id);
console.log('  violations[0].evidence_details[0].observed.source_ref:', patched.violations[0].evidence_details?.[0]?.observed?.source_ref);
