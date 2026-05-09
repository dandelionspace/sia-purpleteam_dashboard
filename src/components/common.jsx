const SEVERITY = {
  Critical: { bg: "#fee4e2", text: "#b42318" },
  High: { bg: "#fff1e6", text: "#b54708" },
  Medium: { bg: "#fef7c3", text: "#854a0e" },
  Low: { bg: "#e7f6ef", text: "#116149" },
};

export function SectionTitle({ title, subtitle }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <h2 style={{ margin: 0, fontSize: 13, fontWeight: 700, color: "#1a1a18", letterSpacing: 0 }}>{title}</h2>
      {subtitle && <p style={{ margin: "5px 0 0", fontSize: 11, color: "#73726c", lineHeight: 1.5 }}>{subtitle}</p>}
    </div>
  );
}

export function Badge({ value }) {
  const style = SEVERITY[value] ?? { bg: "#eef2f6", text: "#344054" };
  return <span style={{ borderRadius: 999, padding: "2px 8px", fontSize: 10, fontWeight: 700, background: style.bg, color: style.text }}>{value ?? "-"}</span>;
}

export function ChipList({ values = [] }) {
  if (!values.length) return <span style={{ color: "#98a2b3" }}>-</span>;
  return (
    <span style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
      {values.slice(0, 3).map((value) => <span key={value} style={{ borderRadius: 4, padding: "2px 7px", background: "#F1F5F9", color: "#475569", fontSize: 10 }}>{value}</span>)}
      {values.length > 3 && <span style={{ borderRadius: 4, padding: "2px 7px", background: "#F1F5F9", color: "#475569", fontSize: 10 }}>+{values.length - 3}</span>}
    </span>
  );
}

export function EmptyRow({ colSpan, text }) {
  return (
    <tr>
      <td colSpan={colSpan} style={{ padding: 28, textAlign: "center", color: "#98a2b3", fontSize: 12 }}>{text}</td>
    </tr>
  );
}
