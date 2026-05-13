import EvidenceSection from "../components/EvidenceSection";

export default function ViolationAnalysisPage({
  violation,
  invariant,
  onBack,
  evidenceEvents = [],
  violations = [],
  invariants = [],
}) {
  return (
    <EvidenceSection
      mode="violation"
      violation={violation}
      invariant={invariant}
      onBack={onBack}
      evidenceEvents={evidenceEvents}
      violations={violations}
      invariants={invariants}
    />
  );
}
