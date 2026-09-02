/**
 * Auth context — stores JWT token and user object globally.
 * Provides login / logout helpers to all child components.
 */
import { createContext, useContext, useState, useEffect } from "react";
import { getMe, logoutSession } from "../api/client";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => sessionStorage.getItem("sw_token"));
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      getMe()
        .then((res) => setUser(res.data))
        .catch(() => {
          setToken(null);
          sessionStorage.removeItem("sw_token");
        })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, [token]);

  const saveToken = (tok) => {
    sessionStorage.setItem("sw_token", tok);
    setToken(tok);
  };

  const logout = async () => {
    try {
      if (token) await logoutSession();
    } finally {
      sessionStorage.removeItem("sw_token");
      setToken(null);
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider value={{ token, user, loading, saveToken, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
