import client from "./client";

export const billingApi = {
  /**
   * Fetch all subscription plan cards.
   * No auth required; backend marks is_current when token present.
   */
  getPlans() {
    return client.get("/api/v1/billing/plans");
  },

  /**
   * Fetch current scan quota usage for the authenticated user.
   */
  getUsage() {
    return client.get("/api/v1/billing/usage");
  },

  /**
   * Fetch the current subscription record.
   * Returns a synthetic free-plan response when no subscription exists.
   */
  getSubscription() {
    return client.get("/api/v1/billing/subscription");
  },

  /**
   * Initiate a plan upgrade via Safepay checkout.
   * @param {string} plan         — "pro" | "enterprise"
   * @param {string} billingCycle — "monthly" | "semester"
   */
  upgrade(plan, billingCycle) {
    return client.post("/api/v1/billing/upgrade", {
      plan,
      billing_cycle: billingCycle,
    });
  },

  /**
   * Cancel the active subscription.
   * Access continues until current_period_end.
   */
  cancel() {
    return client.post("/api/v1/billing/cancel");
  },

  /**
   * Fetch the last 50 billing events for the authenticated user's tenant.
   */
  getHistory() {
    return client.get("/api/v1/billing/history");
  },
};
