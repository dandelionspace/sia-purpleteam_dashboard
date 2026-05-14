import { useMemo, useState } from "react";
import { SectionTitle } from "./common";
import contractSource from "../../GCP_AI_OUTPUT_FRONTEND_SERVING_CONTRACT.source.json";
import { formatServerZone, formatServerZones } from "../utils/zoneDisplay";

const PAGE_SIZE = 20;
const CONTRACT_VIEW_BY_INVARIANT = buildContractViewMap(contractSource);

export default function EvidenceSection({
  evidenceEvents = [],
  violations = [],
  invariants = [],
  mode = "all",
  violation = null,
  invariant = null,
  onBack = null,
}) {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [producerFilter, setProducerFilter] = useState("all");
  const [expandedId, setExpandedId] = useState(null);
  const [viewMode, setViewMode] = useState("timeline");
  const [showEmptyFields, setShowEmptyFields] = useState(false);

  const invariantById = useMemo(() => buildInvariantMap(invariants), [invariants]);
  const evidenceRows = useMemo(
    () => buildEvidenceRows(evidenceEvents, violations, invariantById),
    [evidenceEvents, violations, invariantById]
  );
  const scopedRows = useMemo(
    () => mode === "violation" && violation
      ? filterRowsForViolation(evidenceRows, violation)
      : evidenceRows,
    [evidenceRows, mode, violation]
  );
  const typeRows = useMemo(() => calcEvidenceTypeRows(evidenceRows), [evidenceRows]);
  const scopedTypeRows = useMemo(() => calcEvidenceTypeRows(scopedRows), [scopedRows]);
  const producerRows = useMemo(() => calcProducerVmRows(scopedRows), [scopedRows]);
  const typeOptions = useMemo(() => typeRows.map((row) => row.key), [typeRows]);
  const producerOptions = useMemo(
    () => [...new Set(scopedRows.map((row) => getProducerVm(row)).filter(Boolean))].sort(),
    [scopedRows]
  );
  const filteredRows = useMemo(() => {
    const query = search.trim().toLowerCase();
    return scopedRows.filter((row) => {
      const type = getEvidenceEventType(row);
      const producer = getProducerVm(row);
      const text = [
        row.evidence_id,
        row.trace_id,
        type,
        producer,
        row.producer_component_id ?? row.producer?.component_id,
        row.raw_ref?.source,
        row.observed?.source_ref,
        row.observed?.summary,
        ...Object.values(row.observed ?? {}).flatMap((value) => toList(value)),
        getEvidenceSubject(row),
        ...toList(row.related_invariant_ids),
        ...toList(row.related_violation_ids),
      ].join(" ").toLowerCase();
      return (
        (!query || text.includes(query)) &&
        (typeFilter === "all" || type === typeFilter) &&
        (producerFilter === "all" || producer === producerFilter)
      );
    });
  }, [producerFilter, scopedRows, search, typeFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE));
  const currentPage = Math.min(Math.max(page, 1), totalPages);
  const pageItems = filteredRows.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  function updateSearch(value) {
    setSearch(value);
    setPage(1);
  }

  function updateType(value) {
    setTypeFilter(value);
    setPage(1);
  }

  function updateProducer(value) {
    setProducerFilter(value);
    setPage(1);
  }

  function toggleExpand(id) {
    setExpandedId((prev) => (prev === id ? null : id));
  }

  const analysisVm = mode === "violation" && violation
    ? buildViolationViewModel(violation, invariant, scopedRows)
    : null;

  return (
    <section>
      {onBack && (
        <div style={styles.backRow}>
          <button type="button" onClick={onBack} style={styles.backButton}>← 위반 목록으로</button>
        </div>
      )}

      <SectionTitle
        title={mode === "violation" ? "위반 불변식 상세 분석" : "Evidence 전체 현황"}
        subtitle={mode === "violation"
          ? "선택한 불변식 위반에 매핑된 evidence와 판단 근거를 함께 확인합니다."
          : "수집된 모든 evidence 항목과 위반 매핑을 한 화면에서 확인합니다."}
      />

      {analysisVm ? (
        <>
          <ViolationStickyHeader vm={analysisVm} />
          <div style={styles.analysisWorkspaceGrid}>
            <EvidenceTypeFilterPanel
              rows={scopedTypeRows}
              requiredTypes={analysisVm.requiredEvidenceTypes}
              activeType={typeFilter}
              onSelectType={updateType}
            />
            <ViolationAnalysisPanel vm={analysisVm} rows={scopedRows} />
            <AIJudgmentFlowPanel vm={analysisVm} rows={scopedRows} />
          </div>
          <EvidenceExplorer
            rows={filteredRows}
            pageItems={pageItems}
            currentPage={currentPage}
            totalPages={totalPages}
            setPage={setPage}
            search={search}
            updateSearch={updateSearch}
            typeFilter={typeFilter}
            updateType={updateType}
            typeOptions={scopedTypeRows.map((row) => row.key)}
            producerFilter={producerFilter}
            updateProducer={updateProducer}
            producerOptions={producerOptions}
            viewMode={viewMode}
            setViewMode={setViewMode}
            expandedId={expandedId}
            toggleExpand={toggleExpand}
            showEmptyFields={showEmptyFields}
            setShowEmptyFields={setShowEmptyFields}
            showRelation
          />
        </>
      ) : (
        <>
          <div style={styles.statGrid}>
            <StatCard label="전체 Evidence" value={`${formatNumber(scopedRows.length)}건`} />
            <StatCard label="Event type" value={`${formatNumber(typeRows.length)}종`} />
            <StatCard label="위반 연결" value={`${formatNumber(scopedRows.filter((row) => toList(row.related_violation_ids).length).length)}건`} />
            <StatCard label="수집 VM" value={`${formatNumber(producerOptions.length)}개`} />
          </div>
          <div style={styles.summaryGrid}>
            <EvidenceEventTypesCard rows={typeRows} compact />
            <ProducerVmStatsCard rows={producerRows} />
          </div>
          <EvidenceExplorer
            rows={filteredRows}
            pageItems={pageItems}
            currentPage={currentPage}
            totalPages={totalPages}
            setPage={setPage}
            search={search}
            updateSearch={updateSearch}
            typeFilter={typeFilter}
            updateType={updateType}
            typeOptions={typeOptions}
            producerFilter={producerFilter}
            updateProducer={updateProducer}
            producerOptions={producerOptions}
            viewMode={viewMode}
            setViewMode={setViewMode}
            expandedId={expandedId}
            toggleExpand={toggleExpand}
            showEmptyFields={showEmptyFields}
            setShowEmptyFields={setShowEmptyFields}
          />
        </>
      )}
    </section>
  );
}

function EvidenceEventTypesCard({ rows, compact = false }) {
  const max = Math.max(1, ...rows.map((row) => row.count));
  return (
    <div style={{ ...styles.evidenceEventCard, ...(compact ? styles.evidenceEventCardCompact : null) }}>
      <div style={styles.evidenceEventHeader}>
        <div>
          <h3 style={styles.evidenceEventTitle}>Evidence event types</h3>
          <p style={styles.evidenceEventSubtitle}>raw evidence JSONL에서 관측된 상위 event_type</p>
        </div>
        <span style={styles.evidenceEventBadge}>{rows.length ? `${rows.length} types` : "no data"}</span>
      </div>
      <div style={styles.evidenceEventList}>
        {rows.length ? rows.slice(0, 12).map((row) => (
          <div key={row.key} style={compact ? styles.evidenceEventRowCompact : styles.evidenceEventRow}>
            <span style={styles.evidenceEventLabel} title={row.key}>{row.key}</span>
            <div style={styles.evidenceEventTrack}>
              <div style={{ ...styles.evidenceEventFill, width: `${Math.max(2, Math.round((row.count / max) * 100))}%` }} />
            </div>
            <strong style={styles.evidenceEventValue}>{formatNumber(row.count)}</strong>
          </div>
        )) : (
          <div style={styles.evidenceEventEmpty}>관측된 evidence event_type이 없습니다.</div>
        )}
      </div>
    </div>
  );
}

function ProducerVmStatsCard({ rows }) {
  const max = Math.max(1, ...rows.map((row) => row.count));
  const topVm = rows[0];
  return (
    <div style={styles.producerVmCard}>
      <div style={styles.producerVmHeader}>
        <div>
          <h3 style={styles.evidenceEventTitle}>Producer VM distribution</h3>
          <p style={styles.evidenceEventSubtitle}>evidence를 생성한 VM별 수집량과 편중도를 비교합니다.</p>
        </div>
      </div>
      {topVm && (
        <div style={styles.producerVmInsight}>
          <strong>{topVm.key}</strong>
          <span>{formatNumber(topVm.count)}건, 전체 {topVm.share}%로 가장 많은 evidence를 생성했습니다.</span>
        </div>
      )}
      <div style={styles.producerVmList}>
        {rows.length ? rows.slice(0, 10).map((row) => (
          <div key={row.key} style={styles.producerVmRow}>
            <span style={styles.producerVmName} title={row.key}>{row.key}</span>
            <div style={styles.producerVmTrack}>
              <div style={{ ...styles.producerVmFill, width: `${Math.max(3, Math.round((row.count / max) * 100))}%` }} />
            </div>
            <strong style={styles.producerVmCount}>{formatNumber(row.count)}</strong>
            <span style={styles.producerVmShare}>{row.share}%</span>
          </div>
        )) : (
          <div style={styles.evidenceEventEmpty}>producer VM 정보가 있는 evidence가 없습니다.</div>
        )}
      </div>
    </div>
  );
}

function ViolationStickyHeader({ vm }) {
  const pct = confidencePercent(vm.confidence);
  return (
    <div style={styles.stickyViolationHeader}>
      <div style={styles.stickyMain}>
        <span style={severityBadgeStyle(vm.severity)}>{vm.severity ?? "미분류"}</span>
        <strong style={styles.stickyInvariant}>{vm.invariantId}</strong>
        <h3 style={styles.stickyTitle}>{vm.title}</h3>
      </div>
      <div style={styles.stickyMeta}>
        <div style={styles.confidenceBlock}>
          <span>Confidence {pct}%</span>
          <div style={styles.confidenceTrack}><div style={{ ...styles.confidenceFill, width: `${pct}%` }} /></div>
        </div>
        <span style={styles.stickyMetaPill}>Evidence {formatNumber(vm.evidenceCount)}개</span>
        {vm.testable && <span style={styles.testablePill}>검증 가능</span>}
        {vm.source && <span style={styles.stickySource}>Source: {vm.source}</span>}
      </div>
    </div>
  );
}

function EvidenceTypeFilterPanel({ rows, requiredTypes, activeType, onSelectType }) {
  const max = Math.max(1, ...rows.map((row) => row.count));
  return (
    <aside style={styles.filterPanel}>
      <div style={styles.panelHeader}>
        <h3 style={styles.panelTitle}>Evidence Type Filter</h3>
        <button type="button" style={activeType === "all" ? styles.filterChipActive : styles.filterChip} onClick={() => onSelectType("all")}>All</button>
      </div>
      <div style={styles.filterList}>
        {rows.map((row) => (
          <button
            key={row.key}
            type="button"
            style={activeType === row.key ? styles.eventFilterButtonActive : styles.eventFilterButton}
            onClick={() => onSelectType(row.key)}
          >
            <span style={styles.eventFilterText}>
              <span style={styles.usedBadge}>사용됨</span>
              <span style={styles.eventFilterName}>{row.key}</span>
            </span>
            <strong>{formatNumber(row.count)}</strong>
            <span style={styles.eventFilterMiniTrack}>
              <span style={{ ...styles.eventFilterMiniFill, width: `${Math.max(4, Math.round((row.count / max) * 100))}%` }} />
            </span>
          </button>
        ))}
      </div>
      <div style={styles.requiredPanel}>
        <h4 style={styles.requiredTitle}>필요 증거</h4>
        {requiredTypes.length ? requiredTypes.map((type) => (
          <div key={type} style={styles.requiredRow}>
            <span style={styles.requiredBadge}>필요</span>
            <span style={styles.requiredText}>{type}</span>
            <span style={styles.requiredStatus}>{rows.length ? "matched" : "pending"}</span>
          </div>
        )) : <span style={styles.emptyInline}>required evidence 정보 없음</span>}
      </div>
    </aside>
  );
}

function ViolationAnalysisPanel({ vm, rows }) {
  return (
    <section style={styles.analysisPanel}>
      <div style={styles.analysisCardGrid}>
        <AnalysisSummaryCard title="기대 상태" value={vm.expectedText} />
        <AnalysisSummaryCard title="위반 사유" value={formatViolationReason(vm.violationReason)} />
        <AnalysisSummaryCard title="관측 상태" value={vm.summary} tone="warn" />
        <AnalysisSummaryCard title="레드팀 관점 해석" value={vm.redTeamMeaning} tone="danger" />
      </div>

      <JudgmentFactsPanel vm={vm} />
    </section>
  );
}

function JudgmentFactsPanel({ vm }) {
  return (
    <div style={styles.judgmentFactsCard}>
      <div style={styles.panelHeader}>
        <div>
          <h3 style={styles.panelTitle}>판정 근거 표</h3>
          <p style={styles.panelDescription}>
            AI가 violation.reason에 직접 인용한 핵심 관측값입니다. 연결된 전체 Evidence는 아래 Explorer에서 "연결 Evidence"로 구분됩니다.
          </p>
        </div>
        <span style={styles.panelHint}>{formatNumber(vm.observedFacts.length)} facts</span>
      </div>
      {vm.expectedFromReason && (
        <div style={styles.expectedReasonBox}>
          <span style={styles.basisLabel}>Expected</span>
          <p style={styles.expectedReasonText}>{vm.expectedFromReason}</p>
        </div>
      )}
      {vm.observedFacts.length ? (
        <div style={styles.factTable}>
          <div style={styles.factHeader}>
            <span>Evidence ID</span>
            <span>필드 경로</span>
            <span>관측값</span>
          </div>
          {vm.observedFacts.map((fact, index) => (
            <div key={`${fact.evidenceId}-${fact.field}-${index}`} style={styles.factRow}>
              <code style={styles.factEvidence}>{fact.evidenceId || "-"}</code>
              <span style={styles.factField}>{fact.field || "decision_basis"}</span>
              <span style={isViolationObservedValue(fact.field, fact.value) ? styles.factValueViolation : styles.factValue}>
                {formatDetailValue(fact.value, fact.field)}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <div style={styles.empty}>violation.reason에서 구조화 가능한 관측값을 찾지 못했습니다.</div>
      )}
      {vm.missingRequiredEvidence.length > 0 && (
        <div style={styles.missingEvidenceBox}>
          <span style={styles.basisLabel}>Missing required evidence</span>
          <ChipGroup values={vm.missingRequiredEvidence} max={8} tone="warn" />
        </div>
      )}
    </div>
  );
}

function AnalysisSummaryCard({ title, value, tone = "default" }) {
  const toneStyle = tone === "danger"
    ? styles.analysisSummaryDanger
    : tone === "warn"
      ? styles.analysisSummaryWarn
      : null;
  return (
    <div style={{ ...styles.analysisSummaryCard, ...toneStyle }}>
      <span style={styles.analysisSummaryLabel}>{title}</span>
      <p style={styles.analysisSummaryText}>{value || "-"}</p>
    </div>
  );
}

function DecisionStep({ title, value, last = false }) {
  return (
    <div style={styles.decisionStep}>
      <div style={styles.decisionDot} />
      {!last && <div style={styles.decisionLine} />}
      <div style={styles.decisionBody}>
        <span style={styles.decisionTitle}>{title}</span>
        <p style={styles.decisionText}>{value || "-"}</p>
      </div>
    </div>
  );
}

function AIJudgmentFlowPanel({ vm, rows }) {
  return (
    <aside style={styles.sidePanel}>
      <div style={styles.decisionFlow}>
        <h3 style={styles.panelTitle}>AI 판단 흐름</h3>
        <DecisionStep title="불변식 정의" value={vm.verificationLogic || vm.title} />
        <DecisionStep title="매칭된 증거" value={`${formatNumber(rows.length)}건 연결 · ${vm.eventTypes.join(", ") || "event type 정보 없음"}`} />
        <DecisionStep title="관측된 충돌" value={vm.summary} />
        <DecisionStep title="규칙 판정 결과" value={`${formatViolationReason(vm.violationReason)} / ${vm.severity ?? "미분류"} / ${confidencePercent(vm.confidence)}%`} last />
      </div>
    </aside>
  );
}

function EvidenceExplorer({
  rows,
  pageItems,
  currentPage,
  totalPages,
  setPage,
  search,
  updateSearch,
  typeFilter,
  updateType,
  typeOptions,
  producerFilter,
  updateProducer,
  producerOptions,
  viewMode,
  setViewMode,
  expandedId,
  toggleExpand,
  showEmptyFields,
  setShowEmptyFields,
  showRelation = false,
}) {
  return (
    <div style={styles.card}>
      <div style={styles.explorerHeader}>
        <div>
          <h3 style={styles.explorerTitle}>Evidence 탐색기</h3>
          <p style={styles.explorerSubtitle}>연결 Evidence와 판정 근거로 직접 인용된 Evidence를 타임라인 또는 표로 추적합니다.</p>
        </div>
        <div style={styles.segmentedControl}>
          <button type="button" style={viewMode === "timeline" ? styles.segmentActive : styles.segmentButton} onClick={() => setViewMode("timeline")}>Timeline</button>
          <button type="button" style={viewMode === "table" ? styles.segmentActive : styles.segmentButton} onClick={() => setViewMode("table")}>Table</button>
        </div>
      </div>
      <div style={styles.toolbar}>
        <input
          value={search}
          onChange={(event) => updateSearch(event.target.value)}
          placeholder="Search evidence ID, account, VM, group, trace, invariant..."
          style={styles.search}
        />
        <select value={typeFilter} onChange={(event) => updateType(event.target.value)} style={styles.select}>
          <option value="all">All event types</option>
          {typeOptions.map((type) => <option key={type} value={type}>{type}</option>)}
        </select>
        <select value={producerFilter} onChange={(event) => updateProducer(event.target.value)} style={styles.select}>
          <option value="all">All producer VM</option>
          {producerOptions.map((producer) => <option key={producer} value={producer}>{producer}</option>)}
        </select>
        <label style={styles.toggleLabel}>
          <input type="checkbox" checked={showEmptyFields} onChange={(event) => setShowEmptyFields(event.target.checked)} />
          빈 필드 표시
        </label>
        <span style={styles.tableSubtitle}>
          {rows.length ? `${(currentPage - 1) * PAGE_SIZE + 1}-${Math.min(currentPage * PAGE_SIZE, rows.length)} / ${rows.length}건` : "0건"}
        </span>
      </div>

      {!rows.length ? (
        <div style={styles.empty}>조건에 맞는 evidence가 없습니다.</div>
      ) : viewMode === "timeline" ? (
        <EvidenceTimeline rows={pageItems} expandedId={expandedId} toggleExpand={toggleExpand} showEmptyFields={showEmptyFields} showRelation={showRelation} />
      ) : (
        <EvidenceTable rows={pageItems} currentPage={currentPage} expandedId={expandedId} toggleExpand={toggleExpand} showEmptyFields={showEmptyFields} />
      )}
      {totalPages > 1 && <Pagination page={currentPage} totalPages={totalPages} onPageChange={setPage} />}
    </div>
  );
}

function EvidenceTimeline({ rows, expandedId, toggleExpand, showEmptyFields, showRelation = false }) {
  return (
    <div style={styles.timelineList}>
      {rows.map((ev, index) => {
        const rowId = ev.evidence_id ?? `timeline-${index}`;
        const isExpanded = expandedId === rowId;
        return (
          <div key={rowId} style={styles.timelineItem}>
            <div style={styles.timelineRail}><span style={styles.timelineDot} /></div>
            <button type="button" style={styles.timelineButton} onClick={() => toggleExpand(rowId)}>
              <span style={styles.timelineTime}>{formatDateTime(ev.timestamp ?? ev.collected_at)}</span>
              <strong style={styles.timelineTitle}>{getEvidenceEventType(ev)} · {getProducerVm(ev) || "-"}</strong>
              <span style={styles.timelineSummary}>{getEvidenceSummary(ev)}</span>
              <span style={styles.timelineMeta}>{getEvidenceSubject(ev) || "subject 미확인"} · {ev.trace_id ?? ev.security_context?.trace_id ?? "trace 없음"}</span>
              {showRelation && (getEvidenceRelationshipLabels(ev).length
                ? <span style={styles.timelineRelation}>{getEvidenceRelationshipLabels(ev).join(" · ")}</span>
                : <span style={styles.timelineRelation}>연결 관계 없음</span>)}
            </button>
            {isExpanded && <div style={styles.timelineExpanded}><EvidenceExpandedDetail ev={ev} showEmptyFields={showEmptyFields} /></div>}
          </div>
        );
      })}
    </div>
  );
}

function EvidenceTable({ rows, currentPage, expandedId, toggleExpand, showEmptyFields }) {
  return (
    <table style={styles.table}>
      <colgroup>
        <col style={{ width: 148 }} />
        <col style={{ width: 150 }} />
        <col style={{ width: 160 }} />
        <col style={{ width: 178 }} />
        <col style={{ width: 120 }} />
        <col style={{ width: "auto" }} />
        <col style={{ width: 38 }} />
      </colgroup>
      <thead>
        <tr>
          {["Evidence ID", "관측 시각", "Trace ID", "증거 유형", "수집 VM", "핵심 요약", ""].map((head) => (
            <th key={head} style={styles.th}>{head}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((ev, index) => {
          const rowId = ev.evidence_id ?? `${currentPage}-${index}`;
          const isExpanded = expandedId === rowId;
          return (
            <EvidenceRow
              key={rowId}
              ev={ev}
              isExpanded={isExpanded}
              onToggle={() => toggleExpand(rowId)}
              showEmptyFields={showEmptyFields}
            />
          );
        })}
      </tbody>
    </table>
  );
}

function ViolationContextPanel({ violation, invariant, scopedRows }) {
  const trace = getViolationTrace(violation);
  const title = invariant?.title
    ?? invariant?.name
    ?? invariant?.description
    ?? violation.description
    ?? "불변식 설명이 없습니다.";
  const judgmentSummary = firstNonEmpty(
    violation.judgment_summary,
    violation.summary,
    violation.impact_summary,
    trace.judgment_summary,
    trace.rule_result?.summary,
    violation.reason
  );
  const requiredEvidenceTypes = getRequiredEvidenceTypes(violation, trace, scopedRows);
  const matchedEvidenceIds = getMatchedEvidenceIds(violation, trace, scopedRows);
  const fieldsChecked = getFieldsChecked(violation, trace);
  const missingFields = getMissingFields(violation, trace);
  const decisionBasis = getDecisionBasis(violation, trace);
  const affectedAssets = uniqueList(violation.affected_registry_asset_ids, violation.asset_ids, violation.affected_assets);
  const affectedResources = uniqueList(violation.affected_resource_ids, violation.affected_resources);
  const affectedServices = toList(violation.affected_services);
  const affectedZones = formatServerZones(uniqueList(violation.affected_zones, violation.server_zone, violation.zone));

  return (
    <div style={styles.contextPanel}>
      <div style={styles.contextHeader}>
        <div style={styles.contextTitleBlock}>
          <div style={styles.contextEyebrowRow}>
            <span style={styles.contextEyebrow}>위반 상세</span>
            <span style={styles.invariantId}>{violation.invariant_id ?? "-"}</span>
          </div>
          <h3 style={styles.contextTitle}>{title}</h3>
          <div style={styles.contextPillRow}>
            <span style={styles.reasonPill}>{formatViolationReason(violation.violation_reason)}</span>
            <span style={styles.severityPill}>{violation.severity ?? "미분류"}</span>
            <span style={styles.confidencePill}>신뢰도 {formatConfidence(violation.confidence)}</span>
          </div>
        </div>
        <div style={styles.contextStats}>
          <StatCard label="Evidence" value={`${formatNumber(scopedRows.length)}건`} />
          <StatCard label="심각도" value={violation.severity ?? "미분류"} />
          <StatCard label="신뢰도" value={formatConfidence(violation.confidence)} />
        </div>
      </div>

      <div style={styles.summaryPanel}>
        <span style={styles.summaryPanelLabel}>판단 요약</span>
        <p style={styles.contextText}>{judgmentSummary ?? "판단 요약이 제공되지 않았습니다."}</p>
      </div>

      <div style={styles.detailSectionHeader}>핵심 판단</div>
      <div style={styles.basisGrid}>
        <BasisItem label="위반 유형" value={formatViolationReason(violation.violation_reason)} />
        <BasisItem label="판단 사유" value={violation.reason} />
        <BasisItem label="판단 출처" value={violation.judgment_source ?? trace.judgment_source ?? trace.source} />
        <BasisItem label="검증 가능성" value={formatTestable(violation.current_environment_testable)} />
        <BasisItem label="검증 가능성 사유" value={violation.testability_reason} />
        <BasisItem label="우선순위" value={violation.priority} />
        <BasisItem label="권고 조치" value={violation.remediation} wide />
      </div>

      {(affectedAssets.length || affectedResources.length || affectedServices.length || affectedZones.length) && (
        <>
          <div style={styles.detailSectionHeader}>영향 범위</div>
          <div style={styles.basisGrid}>
            <BasisItem label="영향 자산" value={affectedAssets} />
            <BasisItem label="영향 리소스" value={affectedResources} />
            <BasisItem label="영향 서비스" value={affectedServices} />
            <BasisItem label="영향 존" value={affectedZones} />
          </div>
        </>
      )}

      <div style={styles.tracePanel}>
        <div style={styles.traceHeader}>
          <h3 style={styles.traceTitle}>AI1 Trace</h3>
          <span style={styles.traceHint}>AI 판단 재현에 필요한 근거 필드</span>
        </div>
        <div style={styles.basisGrid}>
          <BasisItem label="Required evidence types" value={requiredEvidenceTypes} />
          <BasisItem label="Matched evidence IDs" value={matchedEvidenceIds} />
          <BasisItem label="Fields checked" value={fieldsChecked} />
          <BasisItem label="Missing fields" value={missingFields.length ? missingFields : "None"} />
          <BasisItem label="Decision basis" value={decisionBasis} wide />
          <BasisItem label="Verification logic" value={trace.invariant?.verification_logic ?? trace.verification_logic} wide />
        </div>
      </div>
    </div>
  );
}

function BasisItem({ label, value, wide = false }) {
  if (value === null || value === undefined || value === "" || (Array.isArray(value) && value.length === 0)) return null;
  return (
    <div style={{ ...styles.basisItem, ...(wide ? styles.basisItemWide : null) }}>
      <span style={styles.basisLabel}>{label}</span>
      {Array.isArray(value) ? (
        <ChipGroup values={value} max={8} />
      ) : (
        <span style={styles.basisValue}>{String(value)}</span>
      )}
    </div>
  );
}

function EvidenceRow({ ev, isExpanded, onToggle, showEmptyFields = false }) {
  const producerVm = getProducerVm(ev);

  return (
    <>
      <tr style={{ ...styles.row, cursor: "pointer" }} onClick={onToggle}>
        <td style={{ ...styles.td, ...styles.monoCell }} title={ev.evidence_id ?? "-"}>{ev.evidence_id ?? "-"}</td>
        <td style={styles.td}>{formatDateTime(ev.timestamp ?? ev.collected_at)}</td>
        <td style={{ ...styles.td, ...styles.monoCell }}>{ev.trace_id ?? ev.security_context?.trace_id ?? "-"}</td>
        <td style={styles.td}><EvidenceTypeBadge type={getEvidenceEventType(ev)} /></td>
        <td style={styles.td}>{producerVm ?? "-"}</td>
        <td style={styles.td}>
          {getEvidenceSubject(ev) && <strong style={styles.rowSubject}>{getEvidenceSubject(ev)}</strong>}
          <span style={styles.rowSummary}>{getEvidenceSummary(ev)}</span>
        </td>
        <td style={{ ...styles.td, textAlign: "center", color: "#98a2b3", fontSize: 11 }}>
          {isExpanded ? "▲" : "▼"}
        </td>
      </tr>
      {isExpanded && (
        <tr>
          <td colSpan={7} style={styles.expandedCell}>
            <EvidenceExpandedDetail ev={ev} showEmptyFields={showEmptyFields} />
          </td>
        </tr>
      )}
    </>
  );
}

function EvidenceExpandedDetail({ ev, showEmptyFields = false }) {
  const sections = buildEvidenceDetailSections(ev);
  const visibleSections = showEmptyFields ? sections : sections.filter((section) => section.entries.length);
  const hiddenSections = sections.filter((section) => !section.entries.length).map((section) => section.key);
  return (
    <div style={styles.expandedGrid}>
      {visibleSections.map((section) => (
        <EvidenceDetailSection key={section.key} section={section} />
      ))}
      {!showEmptyFields && hiddenSections.length > 0 && (
        <div style={styles.hiddenEmptyNote}>값이 없어 숨겨진 섹션: {hiddenSections.join(", ")}</div>
      )}
    </div>
  );
}

function EvidenceDetailSection({ section }) {
  return (
    <div style={styles.detailSection}>
      <div style={styles.detailHeader}>
        <span style={styles.detailTitle}>{section.label}</span>
        <code style={styles.detailKey}>{section.key}</code>
      </div>
      {section.description && <p style={styles.detailDescription}>{section.description}</p>}
      {section.entries.length ? (
        <div style={styles.detailBody}>
          {section.entries.map(([key, value]) => (
            <div key={key} style={styles.detailRow}>
              <span style={styles.detailField}>{formatFieldLabel(key)}</span>
              <span style={isViolationObservedValue(key, value) ? styles.detailValueViolation : styles.detailValue}>{formatDetailValue(value, key)}</span>
            </div>
          ))}
        </div>
      ) : (
        <div style={styles.detailEmpty}>{section.emptyText ?? "표시할 항목이 없습니다."}</div>
      )}
    </div>
  );
}

function ExpandItem({ label, value, mono = false }) {
  if (value === null || value === undefined || value === "" || value === "-") return null;
  return (
    <div style={styles.expandItem}>
      <span style={styles.expandLabel}>{label}</span>
      <span style={mono ? styles.expandMono : styles.expandValue}>{String(value)}</span>
    </div>
  );
}

function StatCard({ label, value }) {
  return (
    <div style={styles.statCard}>
      <span style={styles.statLabel}>{label}</span>
      <strong style={styles.statValue}>{value}</strong>
    </div>
  );
}

function Pagination({ page, totalPages, onPageChange }) {
  const pages = getVisiblePages(page, totalPages);
  return (
    <div style={styles.pagination}>
      <button style={pageBtn(false, page <= 1)} disabled={page <= 1} onClick={() => onPageChange(page - 1)}>‹</button>
      {pages.map((p) => (
        <button key={p} style={pageBtn(p === page)} onClick={() => onPageChange(p)}>{p}</button>
      ))}
      <button style={pageBtn(false, page >= totalPages)} disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}>›</button>
    </div>
  );
}

function EvidenceTypeBadge({ type }) {
  const { bg, color, label } = getEvidenceTypeStyle(type);
  return <span style={{ ...styles.typeBadge, background: bg, color }}>{label}</span>;
}

function ChipGroup({ values, tone = "gray", max = 3 }) {
  const items = toList(values);
  if (!items.length) return <span style={styles.emptyInline}>-</span>;
  const palette = tone === "blue"
    ? { background: "#EEF4FD", color: "#185FA5", borderColor: "#c8ddf0" }
    : tone === "warn"
      ? { background: "#FEF3C7", color: "#92400E", borderColor: "#FDE68A" }
      : { background: "#F5F5F3", color: "#73726c", borderColor: "#e6e3dc" };
  return (
    <span style={styles.chipWrap}>
      {items.slice(0, max).map((value) => <span key={value} style={{ ...styles.chip, ...palette }}>{value}</span>)}
      {items.length > max && <span style={{ ...styles.chip, ...palette }}>+{items.length - max}</span>}
    </span>
  );
}

function buildContractViewMap(source) {
  const map = {};
  const invariantSamples = [
    ...toList(source?.export_tables?.invariants?.sample),
    ...toList(source?.api_shapes?.invariants?.sample),
  ];
  invariantSamples.forEach((item) => {
    const invariantId = item?.invariant_id ?? item?.id;
    if (!invariantId) return;
    map[invariantId] = {
      ...map[invariantId],
      invariant_id: invariantId,
      title: item.title ?? item.description,
      required_evidence: item.required_evidence,
      verification_logic: item.verification_logic,
      severity: item.severity,
    };
  });

  const violationSamples = [
    ...toList(source?.api_shapes?.violations?.sample),
    ...toList(source?.export_tables?.violations?.sample),
    ...toList(source?.api_shapes?.ai2GenerationMetadata?.value?.context?.violations),
  ];
  violationSamples.forEach((item) => {
    const invariantId = item?.invariant_id ?? item?.id;
    if (!invariantId) return;
    map[invariantId] = {
      ...map[invariantId],
      invariant_id: invariantId,
      summary: item.summary,
      reason: item.reason,
      judgment_summary: item.judgment_summary,
      evidence_ids: item.evidence_ids,
      evidence_details: item.evidence_details,
      violation_reason: item.violation_reason,
    };
  });
  return map;
}

function buildViolationViewModel(violation, invariant, scopedRows) {
  const trace = getViolationTrace(violation);
  const contractView = CONTRACT_VIEW_BY_INVARIANT[violation.invariant_id ?? invariant?.id] ?? null;
  const title = invariant?.title
    ?? invariant?.title_ko
    ?? invariant?.name
    ?? invariant?.description
    ?? contractView?.title
    ?? violation.description
    ?? violation.invariant_id
    ?? "불변식 설명이 없습니다.";
  const judgmentSummary = firstNonEmpty(
    contractView?.summary,
    violation.judgment_summary,
    violation.summary,
    violation.impact_summary,
    trace.judgment_summary,
    trace.rule_result?.summary,
    violation.reason
  );
  const reason = firstNonEmpty(violation.reason, trace.rule_result?.reason, contractView?.reason);
  const parsedReason = parseJudgmentReason(reason);
  const verificationLogic = firstNonEmpty(
    contractView?.verification_logic,
    trace.invariant?.verification_logic,
    trace.verification_logic,
    invariant?.verification_logic
  );
  const eventTypes = calcEvidenceTypeRows(scopedRows).map((row) => row.key);
  const primary = scopedRows.find((row) => getEvidenceSubject(row) || getProducerVm(row)) ?? {};
  const source = firstNonEmpty(violation.judgment_source, trace.judgment_source, trace.source, "ai1_rule_precheck");
  return {
    invariantId: violation.invariant_id ?? invariant?.id ?? "-",
    title,
    status: violation.status,
    severity: violation.severity,
    confidence: violation.confidence,
    evidenceCount: scopedRows.length,
    testable: violation.current_environment_testable === true,
    testabilityReason: violation.testability_reason,
    violationReason: violation.violation_reason,
    source,
    summary: judgmentSummary,
    reason,
    requiredEvidenceTypes: uniqueList(contractView?.required_evidence, getRequiredEvidenceTypes(violation, trace, scopedRows)),
    matchedEvidenceIds: getMatchedEvidenceIds(violation, trace, scopedRows),
    verificationLogic,
    expectedText: parsedReason.expected ?? verificationLogic ?? summarizeExpectedState(trace, invariant),
    expectedFromReason: parsedReason.expected,
    observedText: judgmentSummary,
    observedFacts: parsedReason.observedFacts,
    missingRequiredEvidence: uniqueList(parsedReason.missingRequiredEvidence, getMissingFields(violation, trace)),
    redTeamMeaning: inferRedTeamMeaning(violation, scopedRows),
    eventTypes,
    primaryEntity: getEvidenceSubject(primary),
    primaryVm: getProducerVm(primary),
    primaryZone: formatServerZone(primary.producer?.zone ?? primary.producer_zone ?? violation.server_zone ?? violation.zone),
  };
}

function parseJudgmentReason(reason) {
  const text = String(reason ?? "").trim();
  if (!text) {
    return { expected: null, observedFacts: [], missingRequiredEvidence: [] };
  }

  const expectedMatch = text.match(/Expected:\s*([\s\S]*?)(?:\.\s*Observed:|Observed:|$)/i);
  const observedMatch = text.match(/Observed:\s*([\s\S]*)$/i);
  const expected = expectedMatch?.[1]?.replace(/\.\s*$/, "").trim() || null;
  const observedText = observedMatch?.[1]?.trim() || "";
  const missingRequiredEvidence = parseMissingRequiredEvidence(observedText);
  const observedFacts = observedText
    .split(";")
    .map((item) => item.trim().replace(/\.$/, ""))
    .filter(Boolean)
    .flatMap(parseObservedFact)
    .slice(0, 24);

  return { expected, observedFacts, missingRequiredEvidence };
}

function parseObservedFact(item) {
  const missing = item.match(/^missing_required_evidence_types\s*=\s*(.+)$/i);
  if (missing) return [];

  const match = item.match(/^([A-Za-z0-9_-]+)\s+([^=]+?)\s*=\s*(.+)$/);
  if (!match) {
    return [{ evidenceId: "", field: "decision_basis", value: item }];
  }
  return [{
    evidenceId: match[1],
    field: match[2].trim(),
    value: parseReasonValue(match[3].trim()),
  }];
}

function parseMissingRequiredEvidence(text) {
  const match = String(text ?? "").match(/missing_required_evidence_types\s*=\s*\[([^\]]*)\]/i);
  if (!match) return [];
  return match[1]
    .split(",")
    .map((item) => item.trim().replace(/^['"]|['"]$/g, ""))
    .filter(Boolean);
}

function parseReasonValue(value) {
  const normalized = String(value ?? "").trim().replace(/\.$/, "");
  if (/^(true|false)$/i.test(normalized)) return normalized.toLowerCase() === "true";
  if (/^(none|null)$/i.test(normalized)) return "None";
  if (/^-?\d+(\.\d+)?$/.test(normalized)) return Number(normalized);
  return normalized.replace(/^['"]|['"]$/g, "");
}

function summarizeExpectedState(trace, invariant) {
  return firstNonEmpty(
    trace.invariant?.verification_logic,
    trace.verification_logic,
    invariant?.verification_logic,
    invariant?.description,
    "불변식이 요구하는 안전 상태를 만족해야 합니다."
  );
}

function inferRedTeamMeaning(violation, rows) {
  const text = [violation.reason, violation.summary, rows.map(getEvidenceEventType).join(" ")].join(" ").toLowerCase();
  if (text.includes("credential") || text.includes("session") || text.includes("account")) {
    return "비활성 또는 권한 계정을 통한 지속 접근, credential 재사용, 세션 유지 가능성을 검증해야 합니다.";
  }
  if (text.includes("token") || text.includes("jwt")) {
    return "토큰 검증 우회, 폐기 토큰 재사용, 키 접근 경로를 공격 관점에서 재검증해야 합니다.";
  }
  if (text.includes("privileged") || text.includes("admin")) {
    return "권한 상승 또는 과다 권한을 이용한 횡적 이동 가능성을 확인해야 합니다.";
  }
  return "AI 판단 근거가 실제 공격 경로로 이어지는지 동일 자산과 Evidence를 기준으로 검증해야 합니다.";
}

function getEvidenceSubject(event) {
  return firstNonEmpty(
    event?.observed?.account_id,
    event?.observed?.subject_id,
    event?.observed?.actor_id,
    event?.actor?.actor_id,
    event?.actor?.subject_id,
    event?.subject_id,
    event?.account_id,
    event?.producer?.component_id,
    event?.producer?.vm
  );
}

function getEvidenceSummary(event) {
  const observed = event?.observed ?? {};
  const subject = getEvidenceSubject(event);
  const flags = getRiskFlags(event);
  if (observed.summary) return observed.summary;
  if (subject && flags.length) return `${subject} · ${flags.join(", ")}`;
  if (subject) return `${subject} 관련 관측`;
  return event?.raw_ref?.source ?? event?.observed?.source_ref ?? "Evidence summary 없음";
}

function getEvidenceRelationshipLabels(event) {
  const labels = [];
  const relatedViolationIds = toList(event?.related_violation_ids);
  const metadataInvariantIds = toList(event?.observed?.related_invariant_ids);
  if (event?.current_violation_cited) labels.push("판정 근거 인용");
  if (event?.current_violation_linked) labels.push("연결 Evidence");
  if (event?.current_violation_metadata_ref || relatedViolationIds.some((id) => metadataInvariantIds.includes(id))) labels.push("메타 참조");
  if (relatedViolationIds.length > 1) labels.push(`공유 ${relatedViolationIds.length}건`);
  if (event?.evidence_preview_missing) labels.push("preview 없음");
  return labels;
}

function getRiskFlags(event) {
  const observed = event?.observed ?? {};
  const flags = [];
  if (observed.employment_status && observed.employment_status !== "active") flags.push("inactive_subject");
  if (isActiveLike(observed.account_status)) flags.push("account_active");
  if (isActiveLike(observed.credential_status)) flags.push("credential_active");
  if (Number(observed.active_session_count) > 0) flags.push("active_session");
  if (isActiveLike(observed.api_key_status)) flags.push("api_key_active");
  if (isActiveLike(observed.service_token_status)) flags.push("service_token_active");
  if (observed.had_jwt_key_access === true) flags.push("jwt_key_access");
  if (toList(observed.groups).some((group) => /admin|key|priv/i.test(group))) flags.push("privileged_group");
  return flags;
}

function isViolationObservedValue(field, value) {
  const values = toList(value).map((item) => String(item).toLowerCase());
  if (!values.length) return false;
  if (field === "active_session_count") return values.some((item) => Number(item) > 0);
  if (field === "employment_status") return values.some((item) => item && item !== "active");
  if (field === "had_jwt_key_access") return values.includes("true");
  if (/check|validated|validation|performed|allowed|enabled|used/i.test(field)) return values.some((item) => ["false", "none", "null"].includes(item));
  if (field.includes("status")) return values.some(isActiveLike);
  if (field.includes("groups") || field.includes("privilege")) return values.some((item) => /admin|key|priv/i.test(item));
  return false;
}

function isActiveLike(value) {
  return ["active", "enabled", "valid", "allowed", "success", "true"].includes(String(value).toLowerCase());
}

function pickFields(source, keys) {
  return cleanObject(Object.fromEntries(keys.map((key) => [key, source?.[key]])));
}

function confidencePercent(value) {
  if (typeof value !== "number") return 0;
  const normalized = value > 1 ? value / 100 : value;
  return Math.max(0, Math.min(100, Math.round(normalized * 100)));
}

function severityBadgeStyle(severity) {
  const key = String(severity ?? "").toLowerCase();
  const palette = key === "critical"
    ? { background: "#FEF1F1", color: "#B42318", borderColor: "#FECACA" }
    : key === "high"
      ? { background: "#FFF1E8", color: "#B54708", borderColor: "#FED7AA" }
      : key === "medium"
        ? { background: "#FEF7C3", color: "#854D0E", borderColor: "#FDE68A" }
        : { background: "#F1F5F9", color: "#475569", borderColor: "#CBD5E1" };
  return { ...styles.severityBadge, ...palette };
}

function buildEvidenceRows(evidenceEvents, violations, invariantById) {
  const rowsById = new Map();
  const anonymousRows = [];

  toList(evidenceEvents).forEach((event) => addEvidenceRow(event, rowsById, anonymousRows));

  toList(violations).forEach((violation) => {
    const invariantId = violation.invariant_id ?? violation.id;
    const relatedInvariants = [invariantId, ...toList(violation.related_invariants)].filter(Boolean);
    [...toList(violation.evidence_summaries), ...toList(violation.evidence_details)].forEach((event) => {
      addEvidenceRow(event, rowsById, anonymousRows, violation, relatedInvariants);
    });
    toList(violation.evidence_ids).forEach((evidenceId) => {
      const row = rowsById.get(evidenceId);
      const fallback = row ?? { evidence_id: evidenceId, evidence_type: "unknown", evidence_preview_missing: true };
      addEvidenceRow(fallback, rowsById, anonymousRows, violation, relatedInvariants);
    });
  });

  return [...rowsById.values(), ...anonymousRows]
    .map((row) => {
      const observedInvariantIds = toList(row.observed?.related_invariant_ids);
      const relatedInvariantIds = uniqueList(row.related_invariant_ids, observedInvariantIds);
      return {
        ...row,
        related_invariant_ids: relatedInvariantIds,
        related_invariant_titles: relatedInvariantIds
          .map((id) => invariantById[id]?.title ?? invariantById[id]?.description)
          .filter(Boolean),
        related_violation_ids: uniqueList(row.related_violation_ids),
      };
    })
    .sort((a, b) => String(b.timestamp ?? b.collected_at ?? "").localeCompare(String(a.timestamp ?? a.collected_at ?? "")));
}

function filterRowsForViolation(rows, violation) {
  const invariantId = violation?.invariant_id ?? violation?.id;
  const evidenceIds = new Set(toList(violation?.evidence_ids));
  const citedEvidenceIds = new Set(parseJudgmentReason(violation?.reason).observedFacts.map((fact) => fact.evidenceId).filter(Boolean));
  return rows
    .filter((row) => {
      const rowId = row.evidence_id ?? row.id;
      const relatedViolations = toList(row.related_violation_ids);
      return (
        (rowId && evidenceIds.has(rowId)) ||
        (invariantId && relatedViolations.includes(invariantId))
      );
    })
    .map((row) => {
      const rowId = row.evidence_id ?? row.id;
      return {
        ...row,
        current_violation_linked: Boolean(rowId && evidenceIds.has(rowId)),
        current_violation_cited: Boolean(rowId && citedEvidenceIds.has(rowId)),
        current_violation_metadata_ref: Boolean(invariantId && toList(row.observed?.related_invariant_ids).includes(invariantId)),
      };
    });
}

function getViolationTrace(violation) {
  return firstNonEmpty(
    violation?.ai1_trace,
    violation?.ai1Trace,
    violation?.trace,
    violation?.evaluation_trace,
    violation?.ai1_evaluation_trace,
    violation?.raw_violation?.ai1_trace,
    violation?.raw_violation?.trace,
    {}
  ) ?? {};
}

function getRequiredEvidenceTypes(violation, trace, scopedRows) {
  return uniqueList(
    trace.required_evidence_types,
    trace.requiredEvidenceTypes,
    trace.required_evidence,
    trace.invariant?.required_evidence,
    trace.invariant?.required_evidence_types,
    trace.rule_result?.required_evidence_types,
    violation.required_evidence_types,
    violation.required_evidence,
    violation.raw_violation?.required_evidence_types,
    scopedRows.map(getEvidenceEventType)
  );
}

function getMatchedEvidenceIds(violation, trace, scopedRows) {
  return uniqueList(
    trace.matched_evidence_ids,
    trace.matchedEvidenceIds,
    trace.evidence_refs,
    trace.rule_result?.evidence_ids,
    trace.rule_result?.matched_evidence_ids,
    violation.matched_evidence_ids,
    violation.evidence_refs,
    violation.evidence_ids,
    scopedRows.map((row) => row.evidence_id)
  );
}

function getFieldsChecked(violation, trace) {
  return uniqueList(
    trace.fields_checked,
    trace.fieldsChecked,
    trace.invariant?.fields_checked,
    trace.rule_result?.fields_checked,
    violation.fields_checked,
    violation.raw_violation?.fields_checked
  );
}

function getMissingFields(violation, trace) {
  return uniqueList(
    trace.missing_fields,
    trace.missingFields,
    trace.rule_result?.missing_fields,
    violation.missing_evidence_fields,
    violation.raw_violation?.missing_evidence_fields
  );
}

function getDecisionBasis(violation, trace) {
  return firstNonEmpty(
    trace.decision_basis,
    trace.decisionBasis,
    trace.rule_result?.reason,
    trace.rule_result?.decision_basis,
    trace.invariant?.verification_logic,
    violation.judgment_summary,
    violation.reason,
    violation.summary
  );
}

function addEvidenceRow(event, rowsById, anonymousRows, violation = null, relatedInvariants = []) {
  if (!event) return;
  const id = event.evidence_id ?? event.id;
  const relatedViolationId = violation?.invariant_id ?? violation?.id;
  const next = {
    ...event,
    evidence_id: id,
    evidence_type: getEvidenceEventType(event),
    related_violation_ids: uniqueList(event.related_violation_ids, relatedViolationId),
    related_invariant_ids: uniqueList(event.related_invariant_ids, event.observed?.related_invariant_ids, relatedInvariants),
  };

  if (!id) {
    anonymousRows.push(next);
    return;
  }

  const existing = rowsById.get(id);
  if (!existing) {
    rowsById.set(id, next);
    return;
  }

  rowsById.set(id, {
    ...existing,
    ...next,
    related_violation_ids: uniqueList(existing.related_violation_ids, next.related_violation_ids),
    related_invariant_ids: uniqueList(existing.related_invariant_ids, next.related_invariant_ids),
  });
}

function calcEvidenceTypeRows(evidenceRows) {
  const counts = {};
  evidenceRows.forEach((event) => {
    const type = getEvidenceEventType(event);
    counts[type] = (counts[type] ?? 0) + 1;
  });
  return Object.entries(counts)
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

function calcProducerVmRows(evidenceRows) {
  const counts = {};
  evidenceRows.forEach((event) => {
    const producer = getProducerVm(event) || "unknown";
    counts[producer] = (counts[producer] ?? 0) + 1;
  });
  const total = Math.max(1, evidenceRows.length);
  return Object.entries(counts)
    .map(([key, count]) => ({ key, count, share: Math.round((count / total) * 100) }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

function buildInvariantMap(invariants) {
  return Object.fromEntries(
    toList(invariants)
      .map((invariant) => [invariant.invariant_id ?? invariant.id, invariant])
      .filter(([id]) => id)
  );
}

function getEvidenceEventType(event) {
  return event?.evidence_type
    ?? event?.event_type
    ?? event?.observed?.event_type
    ?? event?.source?.event_type
    ?? event?.raw_ref?.source_event_type
    ?? "unknown";
}

function getProducerVm(event) {
  return event?.producer_vm ?? event?.producer?.vm ?? event?.producer_asset_id ?? "";
}

function parseEvidenceSummaryObservation(ev) {
  const summary = ev?.observed?.summary;
  if (!summary || typeof summary !== "string") return null;
  const parts = summary.split("|").map((part) => part.trim()).filter(Boolean);
  if (parts.length < 2) return null;

  const [eventType, , target, decision] = parts;
  const value = cleanObject({
    event_type: eventType,
    target,
    access_decision: decision,
  });

  return Object.keys(value).length >= 2 ? value : null;
}

function buildEvidenceDetailSections(ev) {
  const observed = filterObserved(ev.observed) ?? {};
  const summaryObservation = parseEvidenceSummaryObservation(ev);
  const type = getEvidenceEventType(ev);
  const prioritySections = type === "account_state_event"
    ? [
      {
        key: "identity",
        label: "Identity State",
        description: "계정의 고용/활성 상태와 역할을 우선 확인합니다.",
        value: pickFields(observed, ["account_id", "subject_id", "employment_status", "account_status", "role", "actor_role"]),
      },
      {
        key: "credential_session",
        label: "Credential & Session",
        description: "활성 credential, session, API key, service token은 위반 판단의 핵심 신호입니다.",
        value: pickFields(observed, ["credential_status", "active_session_count", "api_key_status", "service_token_status", "session_status", "token_status"]),
      },
      {
        key: "privilege",
        label: "Privilege Context",
        description: "권한 그룹과 핵심 키 접근 가능성을 확인합니다.",
        value: pickFields(observed, ["groups", "privileges", "permissions", "had_jwt_key_access", "role", "actor_role"]),
      },
      {
        key: "collection_source",
        label: "Collection Source",
        description: "증거가 수집된 VM, 컴포넌트, 원본 경로입니다.",
        value: {
          ...normalizeProducer(ev),
          raw_source: ev.raw_ref?.source ?? ev.observed?.source_ref,
        },
      },
    ]
    : [];

  const genericSections = [
    {
      key: "summary_observation",
      label: "요약에서 추출한 관측값",
      description: "observed.summary에 압축된 이벤트 유형, 영역, 대상 endpoint, access decision을 구조화해서 표시합니다.",
      value: summaryObservation,
    },
    {
      key: "producer",
      label: "수집 주체",
      description: "이 Evidence를 생성하거나 수집한 VM, 컴포넌트 정보입니다.",
      value: normalizeProducer(ev),
    },
    {
      key: "observed",
      label: "관측된 보안 상태/사실",
      description: "Evidence 안에 기록된 관측값입니다. 정책 상태, 계정 상태, 접근 결과 같은 판단 근거가 들어갑니다.",
      value: filterObserved(ev.observed),
    },
    {
      key: "raw_ref",
      label: "증거 수집 출처",
      description: "이 증거가 수집된 원본 파일, 로그, 에이전트, 위치 정보입니다.",
      value: ev.raw_ref,
    },
    {
      key: "actor",
      label: "Actor",
      description: "원본 Evidence의 actor 객체입니다. 비어 있다면 이 Evidence는 명시 행위자를 제공하지 않은 것입니다.",
      value: ev.actor,
    },
    {
      key: "target",
      label: "Target",
      description: "Evidence가 가리키는 대상 자산 또는 리소스입니다.",
      value: ev.target,
    },
    {
      key: "access",
      label: "Access",
      description: "접근 방식, 엔드포인트, 판단 결과 등 접근 이벤트의 세부 정보입니다.",
      value: ev.access,
    },
  ];

  return [...prioritySections, ...genericSections]
    .map((section) => ({ ...section, entries: objectEntries(section.value) }))
    .map((section) => section.entries.length ? section : { ...section, emptyText: `이 Evidence 유형에서는 ${section.key} 정보가 수집 대상이 아니거나 값이 없습니다.` });
}

const OBSERVED_EXCLUDED_KEYS = new Set(["summary", "source_ref", "related_invariant_ids", "scan_id", "event_type", "source_event_id"]);

function filterObserved(observed) {
  if (!observed || typeof observed !== "object" || Array.isArray(observed)) return observed;
  return Object.fromEntries(Object.entries(observed).filter(([key]) => !OBSERVED_EXCLUDED_KEYS.has(key)));
}

function normalizeProducer(ev) {
  const producer = ev.producer && typeof ev.producer === "object" ? ev.producer : {};
  return cleanObject({
    vm: firstNonEmpty(producer.vm, ev.producer_vm),
    component_id: firstNonEmpty(producer.component_id, ev.producer_component_id),
    component_type: firstNonEmpty(producer.component_type, ev.producer_component_type),
    asset_id: firstNonEmpty(producer.asset_id, ev.producer_asset_id),
    service_id: firstNonEmpty(producer.service_id, ev.producer_service_id),
    zone: formatServerZone(firstNonEmpty(producer.zone, ev.producer_zone)),
  });
}

function objectEntries(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return Object.entries(value).filter(([, entryValue]) => (
    entryValue !== null &&
    entryValue !== undefined &&
    entryValue !== "" &&
    !(Array.isArray(entryValue) && entryValue.length === 0) &&
    !(typeof entryValue === "object" && !Array.isArray(entryValue) && Object.keys(entryValue).length === 0)
  ));
}

function cleanObject(value) {
  return Object.fromEntries(
    Object.entries(value).filter(([, entryValue]) => (
      entryValue !== null &&
      entryValue !== undefined &&
      entryValue !== "" &&
      !(Array.isArray(entryValue) && entryValue.length === 0)
    ))
  );
}

function firstNonEmpty(...values) {
  return values.find((value) => (
    value !== null &&
    value !== undefined &&
    value !== "" &&
    !(Array.isArray(value) && value.length === 0)
  ));
}

function uniqueList(...values) {
  return [...new Set(values.flatMap((value) => toList(value)).filter(Boolean))];
}

function toList(value) {
  if (Array.isArray(value)) return value.filter(Boolean);
  return value ? [value] : [];
}

function getVisiblePages(page, totalPages) {
  const maxButtons = 10;
  const blockStart = Math.floor((page - 1) / maxButtons) * maxButtons + 1;
  const blockEnd = Math.min(blockStart + maxButtons - 1, totalPages);
  return Array.from({ length: blockEnd - blockStart + 1 }, (_, index) => blockStart + index);
}

function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("ko-KR", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number.toLocaleString("ko-KR") : String(value ?? "-");
}

function formatConfidence(value) {
  if (typeof value !== "number") return "-";
  const normalized = value > 1 ? value / 100 : value;
  return `${Math.round(normalized * 100)}%`;
}

function formatTestable(value) {
  if (value === true) return "현재 환경 검증 가능";
  if (value === false) return "추가 환경 또는 수집 보강 필요";
  return null;
}

function formatViolationReason(value) {
  const labels = {
    clear_violation: "구조화된 조건값 위반",
    partial_satisfaction: "부분 충족/부분위반",
    evidence_missing: "증거 부족",
    control_not_observed: "통제 미관측",
  };
  return labels[value] ?? value ?? "-";
}

function formatFieldLabel(key) {
  const labels = {
    vm: "수집 VM",
    component_id: "수집 컴포넌트 ID",
    component_type: "컴포넌트 유형",
    zone: "수집 존",
    asset_id: "자산 ID",
    service_id: "서비스 ID",
    account_id: "계정 ID",
    subject_id: "Subject ID",
    role: "역할",
    actor_role: "행위자 역할",
    groups: "소속 그룹",
    privileges: "권한",
    permissions: "권한",
    employment_status: "고용 상태",
    account_status: "계정 상태",
    credential_status: "Credential 상태",
    active_session_count: "활성 세션 수",
    api_key_status: "API Key 상태",
    service_token_status: "Service Token 상태",
    session_status: "세션 상태",
    token_status: "토큰 상태",
    had_jwt_key_access: "JWT Key 접근",
    raw_source: "원본 경로",
    source: "원본 경로",
    agent: "수집 에이전트",
    log_id: "로그 ID",
    location: "수집 위치",
    service: "서비스",
    evidence_category: "증거 분류",
    rate_limited: "수집 제한 여부",
    scan_id: "스캔 ID",
    summary: "요약",
    event_type: "이벤트 유형",
    source_ref: "소스 참조",
    related_invariant_ids: "관련 불변식",
    judgment_summary: "판단 요약",
    decision_reason: "판단 사유",
    contract_expected_observed: "Contract 기준",
    production_customer_data_access_allowed: "운영 고객 데이터 접근",
    plaintext_secret_access_allowed: "평문 비밀정보 접근",
    validate_issuer: "Issuer 검증",
    validate_audience: "Audience 검증",
    validate_iat: "IAT 검증",
    validate_kid_active: "KID 활성 검증",
    validate_jti_registry: "JTI Registry 검증",
    validate_revocation: "폐기 여부 검증",
    revocation_list_enabled: "폐기 목록 활성화",
  };
  return labels[key] ?? key;
}

function formatDetailValue(value, key = "") {
  if (String(key).toLowerCase().includes("zone")) {
    const zones = formatServerZones(value);
    if (zones.length) return zones.join(", ");
  }
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "boolean") return value ? "true" : "false";
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function getEvidenceTypeStyle(type) {
  const map = {
    key_management_state: { bg: "#EEF4FD", color: "#185FA5", label: "key_management_state" },
    privileged_access_event: { bg: "#FEF3C7", color: "#92400E", label: "privileged_access_event" },
    gateway_access_event: { bg: "#E7F6EF", color: "#116149", label: "gateway_access_event" },
    api_authorization_event: { bg: "#F3E8FF", color: "#6B21A8", label: "api_authorization_event" },
    log_trace_state: { bg: "#F1F0EC", color: "#44403C", label: "log_trace_state" },
    aggregation_state: { bg: "#F1F0EC", color: "#44403C", label: "aggregation_state" },
    authz_policy_state: { bg: "#FEF3C7", color: "#92400E", label: "authz_policy_state" },
    token_policy_state: { bg: "#EEF4FD", color: "#185FA5", label: "token_policy_state" },
    wazuh_alert_event: { bg: "#FEF1F1", color: "#C53030", label: "wazuh_alert_event" },
    data_access_event: { bg: "#E7F6EF", color: "#116149", label: "data_access_event" },
    network_policy_state: { bg: "#F3E8FF", color: "#6B21A8", label: "network_policy_state" },
    account_state_event: { bg: "#FEF1F1", color: "#C53030", label: "account_state_event" },
    privileged_access_state: { bg: "#FEF3C7", color: "#92400E", label: "privileged_access_state" },
    token_validation_event: { bg: "#EEF4FD", color: "#185FA5", label: "token_validation_event" },
    identity_auth_event: { bg: "#F3E8FF", color: "#6B21A8", label: "identity_auth_event" },
    object_storage_access_event: { bg: "#E7F6EF", color: "#116149", label: "object_storage_access_event" },
    central_job_metadata: { bg: "#F1F0EC", color: "#44403C", label: "central_job_metadata" },
  };
  return map[type] ?? { bg: "#F1F0EC", color: "#44403C", label: type ?? "unknown" };
}

function pageBtn(active, disabled = false) {
  return {
    minWidth: 30,
    height: 30,
    border: `1px solid ${active ? "#185FA5" : "#e4e7ec"}`,
    borderRadius: 6,
    background: active ? "#185FA5" : disabled ? "#F8FAFC" : "#fff",
    color: active ? "#fff" : disabled ? "#C0C6D0" : "#667085",
    fontSize: 12,
    fontWeight: active ? 700 : 500,
    cursor: disabled ? "not-allowed" : "pointer",
  };
}

const styles = {
  backRow: { marginBottom: 16 },
  backButton: {
    border: "0.5px solid rgba(0,0,0,0.15)",
    borderRadius: 8,
    background: "#fff",
    color: "#475569",
    fontSize: 12,
    fontWeight: 600,
    padding: "7px 14px",
    cursor: "pointer",
  },
  stickyViolationHeader: {
    position: "sticky",
    top: 0,
    zIndex: 5,
    background: "rgba(255,255,255,0.96)",
    border: "1px solid #DCE7F3",
    borderRadius: 8,
    padding: "12px 14px",
    marginBottom: 14,
    boxShadow: "0 8px 20px rgba(16,24,40,0.08)",
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 16,
  },
  stickyMain: { display: "flex", alignItems: "center", gap: 9, minWidth: 0, flex: 1 },
  severityBadge: { display: "inline-flex", alignItems: "center", border: "1px solid", borderRadius: 999, padding: "3px 9px", fontSize: 11, fontWeight: 900 },
  stickyInvariant: { fontFamily: "monospace", fontSize: 13, color: "#185FA5", whiteSpace: "nowrap" },
  stickyTitle: { margin: 0, color: "#111827", fontSize: 15, lineHeight: 1.35, fontWeight: 800, display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" },
  stickyMeta: { display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", justifyContent: "flex-end" },
  confidenceBlock: { display: "grid", gap: 4, minWidth: 116, fontSize: 11, fontWeight: 800, color: "#344054" },
  confidenceTrack: { height: 5, background: "#E4E7EC", overflow: "hidden", borderRadius: 999 },
  confidenceFill: { height: "100%", background: "#185FA5", borderRadius: 999 },
  stickyMetaPill: { background: "#EEF4FD", color: "#185FA5", border: "1px solid #c8ddf0", borderRadius: 999, padding: "3px 8px", fontSize: 11, fontWeight: 800 },
  testablePill: { background: "#E7F6EF", color: "#116149", border: "1px solid #BFE6D1", borderRadius: 999, padding: "3px 8px", fontSize: 11, fontWeight: 800 },
  stickySource: { color: "#667085", fontSize: 11 },
  analysisWorkspaceGrid: { display: "grid", gridTemplateColumns: "minmax(250px, 0.78fr) minmax(0, 1.65fr) minmax(240px, 0.8fr)", gap: 14, alignItems: "start", marginBottom: 16 },
  filterPanel: { background: "#fff", border: "1px solid #E4E7EC", borderRadius: 8, padding: 14, boxShadow: "0 1px 2px rgba(16,24,40,0.04)" },
  panelHeader: { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 10 },
  panelTitle: { margin: 0, color: "#111827", fontSize: 13, fontWeight: 900 },
  panelHint: { color: "#667085", fontSize: 11 },
  filterChip: { border: "1px solid #E4E7EC", background: "#fff", color: "#475569", borderRadius: 999, padding: "3px 8px", fontSize: 11, fontWeight: 800, cursor: "pointer" },
  filterChipActive: { border: "1px solid #185FA5", background: "#EEF4FD", color: "#185FA5", borderRadius: 999, padding: "3px 8px", fontSize: 11, fontWeight: 900, cursor: "pointer" },
  filterList: { display: "grid", gap: 7 },
  eventFilterButton: { border: "1px solid #EEF2F6", background: "#FCFCFD", borderRadius: 6, padding: "8px 9px", display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto", gap: 7, alignItems: "center", textAlign: "left", cursor: "pointer", color: "#111827" },
  eventFilterButtonActive: { border: "1px solid #185FA5", background: "#F0F6FE", borderRadius: 6, padding: "8px 9px", display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto", gap: 7, alignItems: "center", textAlign: "left", cursor: "pointer", color: "#111827" },
  eventFilterText: { display: "flex", alignItems: "center", gap: 6, minWidth: 0 },
  usedBadge: { flexShrink: 0, background: "#EEF4FD", color: "#185FA5", borderRadius: 4, padding: "1px 5px", fontSize: 9, fontWeight: 900 },
  eventFilterName: { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11, fontWeight: 700 },
  eventFilterMiniTrack: { gridColumn: "1 / -1", height: 4, background: "#E4E7EC", overflow: "hidden" },
  eventFilterMiniFill: { display: "block", height: "100%", background: "#185FA5" },
  requiredPanel: { marginTop: 14, paddingTop: 12, borderTop: "1px solid #EEF2F6", display: "grid", gap: 7 },
  requiredTitle: { margin: 0, fontSize: 11, color: "#667085", fontWeight: 900, textTransform: "uppercase" },
  requiredRow: { display: "grid", gridTemplateColumns: "auto minmax(0, 1fr) auto", gap: 6, alignItems: "center", fontSize: 11 },
  requiredBadge: { color: "#92400E", background: "#FEF3C7", borderRadius: 4, padding: "1px 5px", fontSize: 9, fontWeight: 900 },
  requiredText: { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "#111827" },
  requiredStatus: { color: "#116149", fontWeight: 800 },
  analysisPanel: { display: "grid", gap: 14 },
  analysisCardGrid: { display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 10 },
  analysisSummaryCard: { background: "#fff", border: "1px solid #E4E7EC", borderRadius: 8, padding: 12, minHeight: 92 },
  analysisSummaryWarn: { background: "#FFF8ED", borderColor: "#FED7AA" },
  analysisSummaryDanger: { background: "#FEF7F7", borderColor: "#FECACA" },
  analysisSummaryLabel: { display: "block", marginBottom: 7, color: "#667085", fontSize: 10, fontWeight: 900, textTransform: "uppercase" },
  analysisSummaryText: { margin: 0, display: "block", color: "#111827", fontSize: 12, lineHeight: 1.55, fontWeight: 500 },
  panelDescription: { margin: "4px 0 0", color: "#667085", fontSize: 11, lineHeight: 1.45 },
  judgmentFactsCard: { background: "#fff", border: "1px solid #E4E7EC", borderRadius: 8, padding: 14 },
  expectedReasonBox: { background: "#F8FAFC", border: "1px solid #EEF2F6", borderRadius: 6, padding: "9px 10px", marginBottom: 10 },
  expectedReasonText: { margin: "4px 0 0", color: "#111827", fontSize: 12, lineHeight: 1.55, fontWeight: 500 },
  factTable: { display: "grid", border: "1px solid #EEF2F6", borderRadius: 6, overflow: "hidden" },
  factHeader: { display: "grid", gridTemplateColumns: "138px minmax(160px, 1fr) minmax(110px, 0.65fr)", gap: 8, background: "#F8FAFC", color: "#667085", fontSize: 10, fontWeight: 900, padding: "8px 10px", textTransform: "uppercase" },
  factRow: { display: "grid", gridTemplateColumns: "138px minmax(160px, 1fr) minmax(110px, 0.65fr)", gap: 8, alignItems: "center", padding: "8px 10px", borderTop: "1px solid #F2F4F7", fontSize: 11 },
  factEvidence: { color: "#185FA5", fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  factField: { color: "#475569", fontFamily: "monospace", wordBreak: "break-word" },
  factValue: { color: "#111827", background: "#F8FAFC", border: "1px solid #EEF2F6", borderRadius: 5, padding: "3px 7px", wordBreak: "break-word" },
  factValueViolation: { color: "#B42318", background: "#FEF1F1", border: "1px solid #FECACA", borderRadius: 5, padding: "3px 7px", wordBreak: "break-word" },
  missingEvidenceBox: { marginTop: 10, paddingTop: 10, borderTop: "1px solid #EEF2F6" },
  decisionFlow: { background: "#fff", border: "1px solid #DCE7F3", borderRadius: 8, padding: 14 },
  decisionStep: { position: "relative", display: "grid", gridTemplateColumns: "18px minmax(0, 1fr)", gap: 8, paddingBottom: 10 },
  decisionDot: { width: 9, height: 9, borderRadius: 999, background: "#185FA5", marginTop: 4, justifySelf: "center", zIndex: 1 },
  decisionLine: { position: "absolute", left: 8, top: 15, bottom: -2, width: 1, background: "#DCE7F3" },
  decisionBody: { minWidth: 0 },
  decisionTitle: { display: "block", color: "#111827", fontSize: 11, fontWeight: 900 },
  decisionText: { margin: "3px 0 0", color: "#475569", fontSize: 11, lineHeight: 1.5 },
  sidePanel: { display: "grid", gap: 14 },
  meaningPanel: { background: "#FEF7F7", border: "1px solid #FECACA", borderRadius: 8, padding: 14 },
  meaningText: { margin: "8px 0 0", color: "#7A271A", fontSize: 12, lineHeight: 1.65, fontWeight: 700 },
  relatedPanel: { background: "#fff", border: "1px solid #E4E7EC", borderRadius: 8, padding: 14 },
  contextRow: { display: "grid", gridTemplateColumns: "78px minmax(0, 1fr)", gap: 8, padding: "7px 0", borderBottom: "1px solid #F2F4F7", fontSize: 11, color: "#667085" },
  contextMono: { fontFamily: "monospace", wordBreak: "break-all" },
  explorerHeader: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, marginBottom: 12 },
  explorerTitle: { margin: 0, color: "#111827", fontSize: 14, fontWeight: 900 },
  explorerSubtitle: { margin: "4px 0 0", color: "#667085", fontSize: 11 },
  segmentedControl: { display: "inline-flex", border: "1px solid #D0D5DD", borderRadius: 7, overflow: "hidden" },
  segmentButton: { border: 0, background: "#fff", color: "#667085", padding: "7px 10px", fontSize: 11, fontWeight: 800, cursor: "pointer" },
  segmentActive: { border: 0, background: "#185FA5", color: "#fff", padding: "7px 10px", fontSize: 11, fontWeight: 900, cursor: "pointer" },
  toggleLabel: { display: "inline-flex", alignItems: "center", gap: 5, color: "#667085", fontSize: 11, fontWeight: 700 },
  timelineList: { display: "grid", gap: 0, padding: "4px 0" },
  timelineItem: { display: "grid", gridTemplateColumns: "28px minmax(0, 1fr)", position: "relative" },
  timelineRail: { position: "relative", display: "flex", justifyContent: "center" },
  timelineDot: { width: 9, height: 9, borderRadius: 999, background: "#185FA5", marginTop: 18, boxShadow: "0 0 0 4px #EEF4FD" },
  timelineButton: { border: 0, borderBottom: "1px solid #EEF2F6", background: "#fff", padding: "12px 0 12px 6px", textAlign: "left", cursor: "pointer", display: "grid", gap: 4 },
  timelineTime: { color: "#667085", fontSize: 10, fontWeight: 800 },
  timelineTitle: { color: "#111827", fontSize: 12 },
  timelineSummary: { color: "#344054", fontSize: 12, lineHeight: 1.5 },
  timelineMeta: { color: "#667085", fontSize: 11, fontFamily: "monospace" },
  timelineRelation: { color: "#185FA5", fontSize: 11, fontWeight: 400 },
  timelineExpanded: { gridColumn: "2", padding: "10px 0 14px 6px" },
  violationOverviewGrid: { display: "grid", gridTemplateColumns: "minmax(260px, 1fr) minmax(0, 2fr)", gap: 14, alignItems: "start", marginBottom: 16 },
  contextPanel: { background: "#fff", border: "1px solid #DCE7F3", borderRadius: 8, padding: 16, boxShadow: "0 1px 2px rgba(16,24,40,0.04)" },
  contextHeader: { display: "flex", justifyContent: "space-between", gap: 16, alignItems: "flex-start" },
  contextTitleBlock: { flex: 1, minWidth: 0 },
  contextEyebrowRow: { display: "flex", alignItems: "center", gap: 8, marginBottom: 8, flexWrap: "wrap" },
  contextEyebrow: { color: "#0C447C", background: "#E6F1FB", border: "1px solid #c8ddf0", borderRadius: 999, padding: "3px 8px", fontSize: 10, fontWeight: 800 },
  invariantId: { fontFamily: "monospace", fontSize: 12, fontWeight: 800, color: "#185FA5" },
  contextTitle: { margin: "0 0 10px", fontSize: 16, lineHeight: 1.45, color: "#111827" },
  contextText: { margin: 0, fontSize: 12, lineHeight: 1.65, color: "#344054" },
  contextPillRow: { display: "flex", flexWrap: "wrap", gap: 6 },
  reasonPill: { display: "inline-flex", alignItems: "center", minHeight: 22, padding: "2px 8px", borderRadius: 999, background: "#FEF3C7", color: "#92400E", fontSize: 10, fontWeight: 800 },
  severityPill: { display: "inline-flex", alignItems: "center", minHeight: 22, padding: "2px 8px", borderRadius: 999, background: "#FEF1F1", color: "#C53030", fontSize: 10, fontWeight: 800 },
  confidencePill: { display: "inline-flex", alignItems: "center", minHeight: 22, padding: "2px 8px", borderRadius: 999, background: "#F5F5F3", color: "#475569", fontSize: 10, fontWeight: 800 },
  contextStats: { display: "grid", gridTemplateColumns: "repeat(3, minmax(76px, 1fr))", gap: 8, minWidth: 250 },
  summaryPanel: { marginTop: 14, background: "#F8FAFC", border: "1px solid #E4E7EC", borderRadius: 8, padding: "11px 12px" },
  summaryPanelLabel: { display: "block", marginBottom: 5, fontSize: 10, color: "#667085", fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.04em" },
  detailSectionHeader: { marginTop: 14, paddingTop: 12, borderTop: "1px solid #EEF2F6", color: "#111827", fontSize: 12, fontWeight: 800 },
  basisGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 8, marginTop: 8 },
  basisItem: { background: "#FCFCFD", border: "1px solid #EEF2F6", borderRadius: 6, padding: "9px 10px", minWidth: 0 },
  basisItemWide: { gridColumn: "1 / -1" },
  basisLabel: { display: "block", marginBottom: 4, fontSize: 10, color: "#667085", fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.04em" },
  basisValue: { display: "block", fontSize: 11, color: "#111827", lineHeight: 1.45, wordBreak: "break-word" },
  tracePanel: { marginTop: 14, padding: "12px 12px 10px", border: "1px solid #DCE7F3", borderRadius: 8, background: "#F7FBFF" },
  traceHeader: { display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 12, marginBottom: 2 },
  traceTitle: { margin: 0, fontSize: 13, fontWeight: 800, color: "#111827" },
  traceHint: { color: "#667085", fontSize: 11 },
  summaryGrid: { display: "grid", gridTemplateColumns: "minmax(240px, 1fr) minmax(0, 2fr)", gap: 14, alignItems: "stretch", marginBottom: 16 },
  statGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 16 },
  statCard: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 8, padding: "18px 20px", minHeight: 92, display: "flex", flexDirection: "column", justifyContent: "center" },
  statLabel: { display: "block", fontSize: 12, color: "#73726c", marginBottom: 12 },
  statValue: { display: "block", fontSize: 28, color: "#173b70", letterSpacing: 0, fontWeight: 700 },
  evidenceEventCard: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 8, padding: 16, boxShadow: "0 1px 2px rgba(16,24,40,0.04)" },
  evidenceEventCardCompact: { alignSelf: "stretch" },
  evidenceEventHeader: { display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12, paddingBottom: 14, borderBottom: "0.5px solid rgba(0,0,0,0.08)", marginBottom: 14 },
  evidenceEventTitle: { margin: 0, fontSize: 18, lineHeight: 1.2, fontWeight: 800, color: "#111827" },
  evidenceEventSubtitle: { margin: "5px 0 0", fontSize: 12, color: "#667085" },
  evidenceEventBadge: { flexShrink: 0, border: "1px solid #efd5ad", background: "#fff8ee", color: "#9a5a00", borderRadius: 2, padding: "4px 7px", fontSize: 11, fontWeight: 700 },
  evidenceEventList: { display: "grid", gap: 9 },
  evidenceEventRow: { display: "grid", gridTemplateColumns: "minmax(120px, 180px) minmax(0, 1fr) 64px", gap: 10, alignItems: "center", fontSize: 12 },
  evidenceEventRowCompact: { display: "grid", gridTemplateColumns: "minmax(94px, 1fr) minmax(46px, 0.8fr) 48px", gap: 8, alignItems: "center", fontSize: 12 },
  evidenceEventLabel: { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "#111827" },
  evidenceEventTrack: { height: 10, background: "#edf2ef", borderRadius: 0, overflow: "hidden" },
  evidenceEventFill: { height: "100%", background: "#2857a4", borderRadius: 0, transition: "width 0.25s ease" },
  evidenceEventValue: { color: "#111827", fontSize: 12, textAlign: "left", fontWeight: 800 },
  evidenceEventEmpty: { padding: "18px 0", color: "#98a2b3", fontSize: 12 },
  producerVmCard: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 8, padding: 16, boxShadow: "0 1px 2px rgba(16,24,40,0.04)" },
  producerVmHeader: { display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12, paddingBottom: 14, borderBottom: "0.5px solid rgba(0,0,0,0.08)", marginBottom: 12 },
  producerVmInsight: { display: "flex", flexWrap: "wrap", gap: 6, alignItems: "baseline", background: "#F7FBFF", border: "1px solid #DCE7F3", borderRadius: 6, padding: "8px 10px", marginBottom: 12, color: "#344054", fontSize: 12 },
  producerVmList: { display: "grid", gap: 8 },
  producerVmRow: { display: "grid", gridTemplateColumns: "minmax(120px, 170px) minmax(0, 1fr) 58px 48px", gap: 10, alignItems: "center", fontSize: 12 },
  producerVmName: { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "#111827", fontWeight: 700 },
  producerVmTrack: { height: 12, background: "#EEF2F6", borderRadius: 999, overflow: "hidden" },
  producerVmFill: { height: "100%", background: "#116149", borderRadius: 999, transition: "width 0.25s ease" },
  producerVmCount: { color: "#111827", fontSize: 12, textAlign: "right", fontWeight: 900 },
  producerVmShare: { color: "#667085", fontSize: 11, textAlign: "right", fontWeight: 800 },
  card: { background: "#fff", border: "0.5px solid rgba(0,0,0,0.1)", borderRadius: 12, overflow: "hidden", padding: "10px 18px 16px" },
  toolbar: { display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8, marginBottom: 12 },
  search: { minWidth: 320, flex: "1 1 280px", border: "1px solid #d0d5dd", borderRadius: 8, padding: "8px 10px", fontSize: 12, fontFamily: "inherit" },
  select: { border: "1px solid #d0d5dd", borderRadius: 8, padding: "8px 10px", fontSize: 12, fontFamily: "inherit", background: "#fff", color: "#344054" },
  tableSubtitle: { marginLeft: "auto", fontSize: 11, color: "#667085", whiteSpace: "nowrap" },
  table: { width: "100%", borderCollapse: "collapse", tableLayout: "fixed", fontSize: 12 },
  th: { textAlign: "left", padding: "9px 10px", color: "#73726c", borderBottom: "0.5px solid rgba(0,0,0,0.1)", fontWeight: 500, fontSize: 12 },
  td: { padding: "10px 10px", borderBottom: "0.5px solid rgba(0,0,0,0.07)", color: "#1a1a18", verticalAlign: "middle", fontSize: 12 },
  monoCell: { fontFamily: "monospace", fontSize: 11, color: "#185FA5", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  sourceCell: { fontFamily: "monospace", fontSize: 11, color: "#475569", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  row: { background: "#fff" },
  rowSubject: { display: "block", marginBottom: 3, color: "#111827", fontSize: 11 },
  rowSummary: { display: "block", color: "#475569", fontSize: 11, lineHeight: 1.4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  typeBadge: { display: "inline-flex", alignItems: "center", padding: "2px 7px", borderRadius: 999, fontSize: 10, fontWeight: 700, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: "100%" },
  chipWrap: { display: "flex", flexWrap: "wrap", gap: 4 },
  chip: { display: "inline-flex", alignItems: "center", padding: "1px 6px", borderRadius: 999, border: "0.5px solid", fontSize: 10, fontWeight: 400, maxWidth: 90, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  emptyInline: { color: "#b0aea8", fontSize: 11 },
  expandedCell: { padding: "12px 16px", background: "#F8FAFC", borderBottom: "0.5px solid rgba(0,0,0,0.08)" },
  expandedGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: "10px 12px" },
  expandItem: { display: "flex", flexDirection: "column", gap: 3 },
  expandLabel: { fontSize: 10, color: "#73726c", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em" },
  expandValue: { fontSize: 12, color: "#1a1a18", lineHeight: 1.45 },
  expandMono: { fontSize: 11, color: "#475569", fontFamily: "monospace", wordBreak: "break-all" },
  detailSection: { gridColumn: "1 / -1", background: "#fff", border: "1px solid #E4E7EC", borderLeft: "3px solid #185FA5", borderRadius: 8, padding: "12px 14px", boxShadow: "0 1px 2px rgba(16,24,40,0.04)" },
  detailHeader: { display: "flex", alignItems: "center", gap: 8, justifyContent: "space-between", marginBottom: 5 },
  detailTitle: { fontSize: 12, fontWeight: 800, color: "#111827" },
  detailKey: { fontSize: 10, color: "#185FA5", background: "#EEF4FD", borderRadius: 999, padding: "2px 7px" },
  detailDescription: { margin: "0 0 10px", fontSize: 11, color: "#667085", lineHeight: 1.45 },
  detailBody: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 8 },
  detailRow: { minWidth: 0, background: "#F8FAFC", border: "1px solid #EEF2F6", borderRadius: 6, padding: "8px 9px" },
  detailField: { display: "block", marginBottom: 4, fontSize: 10, color: "#667085", fontWeight: 700 },
  detailValue: { display: "block", fontSize: 11, color: "#111827", lineHeight: 1.45, wordBreak: "break-word" },
  detailValueViolation: { display: "inline-flex", fontSize: 11, color: "#B42318", background: "#FEF1F1", border: "1px solid #FECACA", borderRadius: 5, padding: "2px 6px", lineHeight: 1.35, fontWeight: 900, wordBreak: "break-word" },
  detailEmpty: { background: "#F8FAFC", border: "1px dashed #D0D5DD", borderRadius: 6, padding: "10px 12px", color: "#667085", fontSize: 11 },
  hiddenEmptyNote: { gridColumn: "1 / -1", color: "#667085", background: "#F8FAFC", border: "1px dashed #D0D5DD", borderRadius: 6, padding: "8px 10px", fontSize: 11 },
  empty: { padding: "32px 0", textAlign: "center", color: "#73726c", fontSize: 13 },
  pagination: { display: "flex", justifyContent: "center", alignItems: "center", gap: 6, marginTop: 14, flexWrap: "wrap" },
};
