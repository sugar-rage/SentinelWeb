/** Displays the result of a single payload scan. */

const LEVEL_CLASS = {
  Safe:     "level-safe",
  Low:      "level-low",
  Medium:   "level-medium",
  High:     "level-high",
  Critical: "level-critical",
};

export default function ScanResultCard({ result, action, payload }) {
  if (!result) return null;

  const levelClass = LEVEL_CLASS[result.risk_level] ?? "level-safe";
  const detected = result.attack_detected;

  return (
    <div className={`scan-result-card ${detected ? "detected" : "clean"}`}>
      {/* Header */}
      <div className="scan-result-header">
        <span className="scan-status-icon">{detected ? "⚠" : "✓"}</span>
        <span className="scan-status-text">
          {detected ? `Attack Detected: ${result.attack_type}` : "No Attack Detected"}
        </span>
        <span className={`action-badge ${action === "blocked" ? "blocked" : "allowed"}`}>
          {action?.toUpperCase()}
        </span>
      </div>

      {/* Payload */}
      <div className="scan-payload-box">
        <span className="scan-field-label">Payload</span>
        <code className="scan-payload-text">{payload}</code>
      </div>

      {/* Metrics grid */}
      <div className="scan-metrics">
        <div className="scan-metric">
          <span className="metric-label">Risk Level</span>
          <span className={`metric-value badge ${levelClass}`}>{result.risk_level}</span>
        </div>
        <div className="scan-metric">
          <span className="metric-label">Risk Score</span>
          <span className="metric-value">{result.risk_score}</span>
        </div>
        <div className="scan-metric">
          <span className="metric-label">Confidence</span>
          <span className="metric-value">{(result.confidence * 100).toFixed(1)}%</span>
        </div>
        {result.severity && (
          <div className="scan-metric">
            <span className="metric-label">Severity</span>
            <span className="metric-value">{result.severity}</span>
          </div>
        )}
      </div>

      {/* Explanation */}
      {result.explanation && (
        <div className="scan-explanation">
          <span className="scan-field-label">Explanation</span>
          <p>{result.explanation}</p>
        </div>
      )}

      {/* Mitigation */}
      {result.mitigation && (
        <div className="scan-mitigation">
          <span className="scan-field-label">Mitigation</span>
          <p>{result.mitigation}</p>
        </div>
      )}
    </div>
  );
}
