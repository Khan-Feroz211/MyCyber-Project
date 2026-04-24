import client from "./client";

export const scheduledScanApi = {
  list() {
    return client.get("/api/v1/scheduled/jobs");
  },

  create(payload) {
    return client.post("/api/v1/scheduled/jobs", payload);
  },

  delete(jobId) {
    return client.delete(`/api/v1/scheduled/jobs/${jobId}`);
  },

  toggle(jobId) {
    return client.post(`/api/v1/scheduled/jobs/${jobId}/toggle`);
  },

  runNow(jobId) {
    return client.post(`/api/v1/scheduled/jobs/${jobId}/run-now`);
  },
};
