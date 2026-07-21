/**
 * Auth context — stores JWT token and user object globally.
 * Provides login / logout helpers to all child components.
 */
import { createContext, useContext, useState, useEffect } from "react";
import { getMe } from "../api/client";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem("sw_token"));
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      getMe()
        .then((res) => setUser(res.data))
        .catch(() => {
          setToken(null);
          localStorage.removeItem("sw_token");
        })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, [token]);

  const saveToken = (tok) => {
    localStorage.setItem("sw_token", tok);
    setToken(tok);
  };

  const logout = () => {
    localStorage.removeItem("sw_token");
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ token, user, loading, saveToken, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
