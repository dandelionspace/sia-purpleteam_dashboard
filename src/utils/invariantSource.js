export function normalizeInvariantSource(source) {
  const value = String(source ?? "").toLowerCase();
  if (value === "custom" || value === "variable" || value.includes("custom") || value.includes("variable")) {
    return "custom";
  }
  if (value === "fixed" || value.includes("fixed")) {
    return "fixed";
  }
  return value;
}

export function getInvariantSource(item) {
  return normalizeInvariantSource(item?.invariant_source ?? item?.source);
}

export function sourceMatches(source, filter) {
  if (filter === "all") return true;
  return normalizeInvariantSource(source) === normalizeInvariantSource(filter);
}
