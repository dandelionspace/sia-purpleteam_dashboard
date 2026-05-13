const ZONE_LABELS = {
  security: "argos-security",
  sec: "argos-security",
  ops: "argos-ops",
  operation: "argos-ops",
  operations: "argos-ops",
  deploy: "argos-deploy",
  deployment: "argos-deploy",
  dmz: "argos-dmz",
  mgmt: "argos-mgmt",
  management: "argos-mgmt",
  data: "argos-data",
  db: "argos-data",
  database: "argos-data",
  dbzone: "argos-data",
  iot: "argos-iot",
  signing: "argos-signing",
  sigining: "argos-signing",
  sign: "argos-signing",
  signining: "argos-signing",
  "\uBCF4\uC548": "argos-security",
  "\uBCF4\uC548\uB9DD": "argos-security",
  "\uC6B4\uC601": "argos-ops",
  "\uC6B4\uC601\uB9DD": "argos-ops",
  "\uBC30\uD3EC": "argos-deploy",
  "\uBC30\uD3EC\uB9DD": "argos-deploy",
  "\uAD00\uB9AC": "argos-mgmt",
  "\uAD00\uB9AC\uB9DD": "argos-mgmt",
  "\uB370\uC774\uD130": "argos-data",
  "\uB370\uC774\uD130\uB9DD": "argos-data",
  "\uC11C\uBA85": "argos-signing",
  "\uC11C\uBA85\uB9DD": "argos-signing",
};

export function formatServerZone(zone) {
  const key = String(zone ?? "").trim();
  if (!key) return "";

  const lower = key.toLowerCase();
  if (lower.startsWith("argos-")) {
    return ZONE_LABELS[lower.replace(/^argos-/, "")] ?? lower;
  }

  const withoutZonePrefix = lower.replace(/^zone-/, "");
  const compact = withoutZonePrefix.replace(/[\s_-]/g, "");
  return ZONE_LABELS[lower] ?? ZONE_LABELS[withoutZonePrefix] ?? ZONE_LABELS[compact] ?? key;
}

export function formatServerZones(values) {
  const list = Array.isArray(values) ? values : values ? [values] : [];
  return [...new Set(list.map(formatServerZone).filter(Boolean))];
}
