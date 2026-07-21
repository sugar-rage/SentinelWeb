/** Login page — submits credentials to /api/auth/login and stores the JWT. */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { login } from "../api/client";
import { useAuth } from "../context/AuthContext";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError]     = useState("");
  const [loading, setLoading] = useState(false);
  const { saveToken } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await login(username, password);
      saveToken(res.data.access_token);
      navigate("/dashboard");
    } catch (err) {
      setError(
        err.response?.data?.detail ?? "Login failed. Check your credentials."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      {/* Animated background blobs */}
      <div className="blob blob-1" />
      <div className="blob blob-2" />

      <div className="login-card">
        {/* Logo */}
        <div className="login-logo">
          <span className="logo-icon-lg">⬡</span>
          <h1 className="login-title">
            Sentinel<span className="logo-accent">Web</span>
          </h1>
          <p className="login-subtitle">AI-Powered Web Security Platform</p>
        </div>

        <form className="login-form" onSubmit={handleSubmit} id="login-form">
          <div className="form-group">
            <label htmlFor="username-input">Username</label>
            <input
              id="username-input"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              autoComplete="username"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="password-input">Password</label>
            <input
              id="password-input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              autoComplete="current-password"
              required
            />
          </div>

          {error && <div className="login-error" role="alert">{error}</div>}

          <button
            id="login-submit-btn"
            type="submit"
            className="btn btn-primary btn-full"
            disabled={loading}
          >
            {loading ? <span className="spinner-sm" /> : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}
