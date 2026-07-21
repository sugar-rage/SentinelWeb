/**
 * Axios API client for SentinelWeb backend.
 *
 * baseURL is intentionally empty so every request goes through the
 * Vite dev-server proxy (/api/* → http://127.0.0.1:8000).
 * This avoids cross-origin requests from the browser and removes the
 * need to handle CORS manually in development.
 */
import axios from "axios";

const client = axios.create({
  baseURL: "",
  headers: { "Content-Type": "application/json" },
});

// Attach JWT token from localStorage to every request
client.interceptors.request.use((config) => {
  const token = localStorage.getItem("sw_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Reject errors normally — AuthContext handles 401 by clearing the token.
// Do NOT use window.location.href here: it causes redirect loops when
// AuthContext calls getMe() on startup with an expired/missing token.
client.interceptors.response.use(
  (res) => res,
  (err) => Promise.reject(err)
);

// ── Auth ──────────────────────────────────────────────────────────
export const login = (username, password) =>
  client.post("/api/auth/login", { username, password });

export const getMe = () => client.get("/api/auth/me");

// ── Dashboard ─────────────────────────────────────────────────────
export const getStats = () => client.get("/api/dashboard/stats");
export const getAttackDistribution = () =>
  client.get("/api/dashboard/attack-distribution");
export const getAttackFrequency = (days = 30) =>
  client.get(`/api/dashboard/attack-frequency?days=${days}`);
export const getTotalRequests = () =>
  client.get("/api/dashboard/total-requests");

// ── Scanner ───────────────────────────────────────────────────────
export const scanPayload = (payload) =>
  client.post("/api/scan", { payload });

// ── Reports ───────────────────────────────────────────────────────
export const generateReport = (start_date = null, end_date = null) =>
  client.post("/api/reports/generate", { start_date, end_date });
