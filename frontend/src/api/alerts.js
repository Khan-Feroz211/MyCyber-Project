import client from "./client";

export const alertApi = {
  /**
   * Fetch a paginated list of alerts.
   * @param {boolean} [includeAcknowledged=false]
   * @param {number}  [page=1]
   * @param {number}  [pageSize=20]
   */
  getAlerts(includeAcknowledged = false, page = 1, pageSize = 20) {
    return client.get("/api/v1/alerts", {
      params: {
        include_acknowledged: includeAcknowledged,
        page,
        page_size: pageSize,
      },
    });
  },

  /**
   * Fetch the total count of unacknowledged alerts.
   */
  getAlertCount() {
    return client.get("/api/v1/alerts/count");
  },

  /**
   * Acknowledge a specific alert.
   * @param {string|number} alertId
   */
  acknowledge(alertId) {
    return client.post("/api/v1/alerts/acknowledge", { alert_id: alertId });
  },

  /**
   * Acknowledge all unacknowledged alerts for the current tenant.
   */
  acknowledgeAll() {
    return client.post("/api/v1/alerts/acknowledge-all");
  },

  /**
   * Delete a specific alert.
   * @param {string|number} alertId
   */
  deleteAlert(alertId) {
    return client.delete(`/api/v1/alerts/${alertId}`);
  },
};
