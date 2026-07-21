/**
 * Dashboard page — stats cards, attack distribution pie chart,
 * and daily attack frequency line chart (via Recharts).
 */
import { useEffect, useState } from "react";
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
} from "recharts";
import {
  getStats,
  getAttackDistribution,
  getAttackFrequency,
  getTotalRequests,
} from "../api/client";
import StatCard from "../components/StatCard";

const PIE_COLORS = ["#7c3aed", "#06b6d4", "#f59e0b", "#ef4444", "#10b981"];

export default function DashboardPage() {
  const [stats, setStats]   = useState(null);
  const [dist, setDist]     = useState([]);
  const [freq, setFreq]     = useState([]);
  const [totalReq, setTotalReq] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]   = useState("");

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [s, d, f, r] = await Promise.all([
          getStats(),
          getAttackDistribution(),
          getAttackFrequency(30),
          getTotalRequests(),
        ]);
        setStats(s.data);
        setDist(d.data);
        setFreq(f.data);
        setTotalReq(r.data.total_requests);
      } catch (e) {
        setError("Failed to load dashboard data. Is the backend running?");
      } finally {
        setLoading(false);
      }
    };
    fetchAll();
  }, []);

  if (loading) return <div className="full-center"><div className="spinner" /></div>;
  if (error) return <div className="error-banner">{error}</div>;

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Dashboard</h1>
        <span className="page-badge">Live</span>
      </div>

      {/* Stat cards */}
      <div className="stat-grid">
        <StatCard
          icon="⟳"
          label="Total Scans"
          value={stats?.total_scans}
          accent="accent-blue"
        />
        <StatCard
          icon="⚠"
          label="Attacks Detected"
          value={stats?.attacks_detected}
          accent="accent-red"
        />
        <StatCard
          icon="⊘"
          label="Blocked"
          value={stats?.blocked_requests}
          accent="accent-purple"
        />
        <StatCard
          icon="✓"
          label="Allowed"
          value={stats?.allowed_requests}
          accent="accent-green"
        />
        <StatCard
          icon="⊡"
          label="Total HTTP Requests"
          value={totalReq}
          accent="accent-cyan"
        />
        <StatCard
          icon="★"
          label="Top Attack"
          value={stats?.top_attack_type ?? "None"}
          accent="accent-amber"
        />
      </div>

      {/* Charts row */}
      <div className="charts-row">
        {/* Attack distribution pie */}
        <div className="chart-card">
          <h2 className="chart-title">Attack Distribution</h2>
          {dist.length === 0 ? (
            <p className="no-data">No attacks recorded yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={dist}
                  dataKey="count"
                  nameKey="attack_type"
                  cx="50%"
                  cy="50%"
                  outerRadius={100}
                  label={({ name, percent }) =>
                    `${name} ${(percent * 100).toFixed(0)}%`
                  }
                >
                  {dist.map((_, idx) => (
                    <Cell
                      key={idx}
                      fill={PIE_COLORS[idx % PIE_COLORS.length]}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "#1e1e2e", border: "1px solid #3b3b52", borderRadius: 8 }}
                  labelStyle={{ color: "#cdd6f4" }}
                />
                <Legend
                  wrapperStyle={{ color: "#cdd6f4" }}
                  formatter={(v) => <span style={{ color: "#cdd6f4" }}>{v}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Daily frequency area chart */}
        <div className="chart-card">
          <h2 className="chart-title">Daily Attacks (Last 30 days)</h2>
          {freq.length === 0 ? (
            <p className="no-data">No data for the selected period.</p>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={freq} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="attackGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#7c3aed" stopOpacity={0.6} />
                    <stop offset="95%" stopColor="#7c3aed" stopOpacity={0.05} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#2a2a3e" />
                <XAxis
                  dataKey="date"
                  tick={{ fill: "#6c7086", fontSize: 11 }}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: "#6c7086", fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip
                  contentStyle={{ background: "#1e1e2e", border: "1px solid #3b3b52", borderRadius: 8 }}
                  labelStyle={{ color: "#cdd6f4" }}
                />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="#7c3aed"
                  strokeWidth={2}
                  fill="url(#attackGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
}
