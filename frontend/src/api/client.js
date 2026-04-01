import axios from "axios";

const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "",
  timeout: 30000,
});

// Request interceptor: attach Bearer token from localStorage
client.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("mycyber_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: handle 401 by clearing session and redirecting
client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem("mycyber_token");
      localStorage.removeItem("mycyber_email");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

export default client;
