import client from "./client";

export const adminSecurityApi = {
  listIncidents(params = {}) {
    return client.get("/api/v1/admin/security/incidents", { params });
  },

  lockUser(userId, reason, lockMinutes = 60) {
    return client.post("/api/v1/admin/security/respond/lock-user", {
      user_id: userId,
      reason,
      lock_minutes: lockMinutes,
    });
  },

  unlockUser(userId, reason) {
    return client.post("/api/v1/admin/security/respond/unlock-user", {
      user_id: userId,
      reason,
    });
  },

  deactivateUser(userId, reason) {
    return client.post("/api/v1/admin/security/respond/deactivate-user", {
      user_id: userId,
      reason,
    });
  },

  reactivateUser(userId, reason) {
    return client.post("/api/v1/admin/security/respond/reactivate-user", {
      user_id: userId,
      reason,
    });
  },
};
