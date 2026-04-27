import client from "./client";

export const scheduledScanApi = {
  /**
   * List all scheduled scan jobs.
   */
  listJobs() {
    return client.get("/api/v1/scheduled/jobs");
  },

  /**
   * Create a new scheduled scan job.
   * @param {Object} data - { name, scan_type, target, schedule_cron }
   */
  createJob(data) {
    return client.post("/api/v1/scheduled/jobs", data);
  },

  /**
   * Delete a scheduled scan job.
   * @param {string} jobId
   */
  deleteJob(jobId) {
    return client.delete(`/api/v1/scheduled/jobs/${jobId}`);
  },

  /**
   * Toggle active/inactive state of a scheduled scan.
   * @param {string} jobId
   */
  toggleJob(jobId) {
    return client.post(`/api/v1/scheduled/jobs/${jobId}/toggle`);
  },

  /**
   * Run a scheduled scan immediately.
   * @param {string} jobId
   */
  runNow(jobId) {
    return client.post(`/api/v1/scheduled/jobs/${jobId}/run-now`);
  },
};
