import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { useNavigate } from "react-router-dom";
import { authApi } from "../api/auth";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const refreshUser = useCallback(async () => {
    const res = await authApi.me();
    setUser(res.data);
    return res.data;
  }, []);

  // On mount: restore session from localStorage and validate token
  useEffect(() => {
    const storedToken = localStorage.getItem("mycyber_token");
    if (!storedToken) {
      setLoading(false);
      return;
    }

    setToken(storedToken);

    authApi
      .me()
      .then((res) => {
        setUser(res.data);
      })
      .catch(() => {
        // Invalid / expired token — clear everything
        localStorage.removeItem("mycyber_token");
        localStorage.removeItem("mycyber_email");
        setToken(null);
        setUser(null);
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  /**
   * Authenticate the user and persist the session.
   * @param {string} email
   * @param {string} password
   */
  const login = useCallback(async (email, password, mfaCode) => {
    const res = await authApi.login(email, password, mfaCode);
    const accessToken = res.data.access_token;

    localStorage.setItem("mycyber_token", accessToken);
    localStorage.setItem("mycyber_email", email);
    setToken(accessToken);

    try {
      // Fetch full user profile after login
      const meRes = await authApi.me();
      setUser(meRes.data);
      return meRes.data;
    } catch (err) {
      // me() failed — roll back the session so state stays consistent
      localStorage.removeItem("mycyber_token");
      localStorage.removeItem("mycyber_email");
      setToken(null);
      setUser(null);
      throw err;
    }
  }, []);

  /**
   * Sign the user out and redirect to the login page.
   */
  const logout = useCallback(() => {
    localStorage.removeItem("mycyber_token");
    localStorage.removeItem("mycyber_email");
    setToken(null);
    setUser(null);
    navigate("/login");
  }, [navigate]);

  /**
   * Register a new account.
   * The caller is responsible for navigating the user to login after success.
   * Any API error is re-thrown so the caller can display it.
   * @param {string} email
   * @param {string} password
   * @param {string} fullName
   */
  const register = useCallback(async (email, password, fullName) => {
    const res = await authApi.register(email, password, fullName);
    return res.data;
  }, []);

  const isAuthenticated = useMemo(() => !!token, [token]);

  const value = useMemo(
    () => ({
      user,
      token,
      loading,
      isAuthenticated,
      login,
      logout,
      register,
      refreshUser,
    }),
    [user, token, loading, isAuthenticated, login, logout, register, refreshUser]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/**
 * Hook to access the auth context.
 * Must be used inside <AuthProvider>.
 */
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
