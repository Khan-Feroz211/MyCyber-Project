import client from "./client";

export const scanApi = {
  /**
   * Scan a text payload for sensitive data.
   * @param {string} text
   * @param {string} [context]
   */
  scanText(text, context) {
    return client.post("/api/v1/scan/text", { text, context });
  },

  /**
   * Scan a base64-encoded file for sensitive data.
   * @param {string} filename
   * @param {string} contentB64
   */
  scanFile(filename, contentB64) {
    return client.post("/api/v1/scan/file", {
      filename,
      content_base64: contentB64,
    });
  },

  /**
   * Scan a network payload for sensitive data.
   * @param {*} payload
   * @param {string} sourceIp
   * @param {string} destination
   * @param {string} protocol
   */
  scanNetwork(payload, sourceIp, destination, protocol) {
    return client.post("/api/v1/scan/network", {
      payload,
      source_ip: sourceIp,
      destination_ip: destination,
    });
  },

  /**
   * Fetch paginated scan history.
   * @param {number} [page=1]
   * @param {number} [pageSize=20]
   * @param {string} [severity]
   * @param {string} [scanType]
   */
  getHistory(page = 1, pageSize = 20, severity, scanType) {
    const params = { page, page_size: pageSize };
    if (severity) params.severity = severity;
    if (scanType) params.scan_type = scanType;
    return client.get("/api/v1/scan/history", { params });
  },

  /**
   * Fetch aggregated scan statistics.
   */
  getStats() {
    return client.get("/api/v1/scan/stats/summary");
  },

  /**
   * Fetch a single scan result by ID.
   * @param {string|number} scanId
   */
  getScanById(scanId) {
    return client.get(`/api/v1/scan/${scanId}`);
  },
};
