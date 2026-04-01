import client from "./client";

export const authApi = {
  /**
   * Authenticate with the server using form-encoded credentials.
   * @param {string} email
   * @param {string} password
   */
  login(email, password) {
    const params = new URLSearchParams();
    params.append("username", email);
    params.append("password", password);
    return client.post("/api/v1/auth/login", params, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
  },

  /**
   * Create a new account.
   * @param {string} email
   * @param {string} password
   * @param {string} fullName
   */
  register(email, password, fullName) {
    return client.post("/api/v1/auth/register", {
      email,
      password,
      full_name: fullName,
    });
  },

  /**
   * Fetch the currently authenticated user's profile.
   */
  me() {
    return client.get("/api/v1/auth/me");
  },
};
