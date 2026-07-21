/** Left sidebar navigation with animated links and logo. */
import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const LINKS = [
  { to: "/dashboard", icon: "⬡", label: "Dashboard" },
  { to: "/scanner",   icon: "⟳", label: "Scanner"   },
  { to: "/reports",   icon: "☰", label: "Reports"   },
];

export default function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <span className="logo-icon">⬡</span>
        <span className="logo-text">Sentinel<span className="logo-accent">Web</span></span>
      </div>

      {/* Nav links */}
      <nav className="sidebar-nav">
        {LINKS.map(({ to, icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              "sidebar-link" + (isActive ? " active" : "")
            }
          >
            <span className="link-icon">{icon}</span>
            <span className="link-label">{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* User badge + logout at bottom */}
      <div className="sidebar-footer">
        {user && (
          <div className="user-badge">
            <div className="user-avatar">
              {user.username?.[0]?.toUpperCase() ?? "U"}
            </div>
            <div className="user-info">
              <span className="user-name">{user.username}</span>
              <span className="user-role">{user.role}</span>
            </div>
          </div>
        )}
        <button className="logout-btn" onClick={handleLogout} id="logout-btn">
          ⏻ Logout
        </button>
      </div>
    </aside>
  );
}
