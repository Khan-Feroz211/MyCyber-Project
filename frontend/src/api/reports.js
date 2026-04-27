import client from "./client";

export const reportsApi = {
  exportCsv(params = {}) {
    return client.get("/api/v1/reports/export/csv", { params, responseType: "blob" });
  },

  exportHtml(params = {}) {
    return client.get("/api/v1/reports/export/html", { params });
  },

  exportJson(params = {}) {
    return client.get("/api/v1/reports/export/json", { params });
  },
};
