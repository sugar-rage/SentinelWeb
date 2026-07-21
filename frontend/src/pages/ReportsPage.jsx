/**
 * Reports page — generate a security report (optionally filtered by
 * date range) and display it as a sortable table.
 */
import { useState } from "react";
import { generateReport } from "../api/client";

const RISK_CLASS = {
  Safe:     "level-safe",
  Low:      "level-low",
  Medium:   "level-medium",
  High:     "level-high",
  Critical: "level-critical",
};

export default function ReportsPage() {
  const [startDate, setStartDate] = useState("");
  const [endDate,   setEndDate]   = useState("");
  const [report,    setReport]    = useState(null);
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState("");

  const handleGenerate = async (e) => {
    e.preventDefault();
    setError("");
    setReport(null);
    setLoading(true);
    try {
      const res = await generateReport(
        startDate || null,
        endDate   || null,
      );
      setReport(res.data);
    } catch (err) {
      setError(err.response?.data?.detail ?? "Failed to generate report.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Security Reports</h1>
      </div>

      {/* Controls */}
      <form className="report-controls" onSubmit={handleGenerate} id="report-form">
        <div className="form-group report-form-group">
          <label htmlFor="report-start">From</label>
          <input
            id="report-start"
            type="date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
          />
        </div>
        <div className="form-group report-form-group">
          <label htmlFor="report-end">To</label>
          <input
            id="report-end"
            type="date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
          />
        </div>
        <button
          id="generate-report-btn"
          type="submit"
          className="btn btn-primary"
          disabled={loading}
        >
          {loading ? <><span className="spinner-sm" /> Generating…</> : "☰ Generate Report"}
        </button>
      </form>

      {error && <div className="login-error">{error}</div>}

      {/* Summary cards */}
      {report && (
        <>
          <div className="report-summary">
            <div className="report-summary-card">
              <span className="rs-value">{report.total_events}</span>
              <span className="rs-label">Total Events</span>
            </div>
            <div className="report-summary-card accent-red">
              <span className="rs-value">{report.attacks_found}</span>
              <span className="rs-label">Attacks</span>
            </div>
            <div className="report-summary-card accent-purple">
              <span className="rs-value">{report.blocked_count}</span>
              <span className="rs-label">Blocked</span>
            </div>
            <div className="report-summary-card accent-green">
              <span className="rs-value">{report.allowed_count}</span>
              <span className="rs-label">Allowed</span>
            </div>
          </div>

          {/* Table */}
          <div className="table-wrapper">
            <table className="report-table" id="report-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Timestamp</th>
                  <th>Attack Type</th>
                  <th>Risk Level</th>
                  <th>Risk Score</th>
                  <th>Confidence</th>
                  <th>Action</th>
                  <th>Payload</th>
                </tr>
              </thead>
              <tbody>
                {report.entries.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ textAlign: "center", padding: "2rem", color: "var(--text-muted)" }}>
                      No entries in this date range.
                    </td>
                  </tr>
                ) : (
                  report.entries.map((e, idx) => (
                    <tr key={e.id} className={e.attack_type ? "row-attack" : ""}>
                      <td>{idx + 1}</td>
                      <td className="cell-mono">
                        {new Date(e.timestamp).toLocaleString()}
                      </td>
                      <td>{e.attack_type ?? <span className="text-muted">—</span>}</td>
                      <td>
                        <span className={`badge ${RISK_CLASS[e.risk_level] ?? "level-safe"}`}>
                          {e.risk_level}
                        </span>
                      </td>
                      <td>{e.risk_score}</td>
                      <td>{e.confidence != null ? `${(e.confidence * 100).toFixed(1)}%` : "—"}</td>
                      <td>
                        <span className={`action-badge ${e.action === "blocked" ? "blocked" : "allowed"}`}>
                          {e.action?.toUpperCase()}
                        </span>
                      </td>
                      <td className="cell-payload">
                        <code>{e.raw_payload?.slice(0, 60)}{e.raw_payload?.length > 60 ? "…" : ""}</code>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
