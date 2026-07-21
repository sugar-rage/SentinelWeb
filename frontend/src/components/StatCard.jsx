/** Glassmorphism stat card for the dashboard overview. */
export default function StatCard({ label, value, sub, accent, icon }) {
  return (
    <div className={`stat-card ${accent ?? ""}`}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-body">
        <div className="stat-value">{value ?? "—"}</div>
        <div className="stat-label">{label}</div>
        {sub && <div className="stat-sub">{sub}</div>}
      </div>
    </div>
  );
}
