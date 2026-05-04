import client from "./client";

export const llmDlpApi = {
  /**
   * Send a prompt through the LLM DLP pipeline.
   * @param {string} prompt
   * @param {Object} options - { provider?, model?, skipRedaction? }
   */
  chat(prompt, options = {}) {
    const { provider, model, skipRedaction } = options;
    return client.post("/api/v1/llm-dlp/chat", {
      prompt,
      provider,
      model,
      skip_redaction: skipRedaction,
    });
  },

  /**
   * Get paginated LLM DLP interaction history.
   * @param {number} page
   * @param {number} pageSize
   * @param {string|null} statusFilter
   */
  getHistory(page = 1, pageSize = 20, statusFilter = null) {
    const params = { page, page_size: pageSize };
    if (statusFilter) params.status_filter = statusFilter;
    return client.get("/api/v1/llm-dlp/history", { params });
  },

  /**
   * Get detail of a single interaction.
   * @param {string} interactionId
   */
  getDetail(interactionId) {
    return client.get(`/api/v1/llm-dlp/history/${interactionId}`);
  },

  /**
   * Get LLM DLP dashboard stats.
   */
  getStats() {
    return client.get("/api/v1/llm-dlp/stats");
  },
};
