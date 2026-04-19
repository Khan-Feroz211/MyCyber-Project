import React from "react";
import { Link } from "react-router-dom";
import Footer from "../../components/layout/Footer";

const sections = [
  {
    title: "1. Acceptance of Terms",
    body: [
      "These Terms of Service (\"Terms\") govern your use of the MyCyber DLP platform and related services. By creating an account, accessing, or using MyCyber, you agree to be bound by these Terms.",
      "If you are accepting on behalf of an organization, you represent that you have authority to bind that organization.",
    ],
  },
  {
    title: "2. Description of Service",
    body: [
      "MyCyber provides an AI-powered Data Leakage Prevention (DLP) platform that scans text, file content, and related data streams to identify sensitive information and provide risk decisions such as BLOCK, WARN, or ALLOW.",
      "Service features may evolve over time to improve security, reliability, and performance.",
    ],
  },
  {
    title: "3. Account Registration and Security",
    body: [
      "You are responsible for maintaining the confidentiality of account credentials and for all activities under your account.",
      "You must provide accurate and current registration information and promptly update it when changes occur.",
      "Unless explicitly approved in writing, each organization should maintain a single primary account structure and authorized team access through designated controls.",
    ],
  },
  {
    title: "4. Acceptable Use Policy",
    body: [
      "Permitted use: You may use MyCyber to scan data you own or are legally authorized to process.",
      "Prohibited use: You may not scan data you do not own or control, reverse engineer platform internals, bypass security controls, or resell the service without a separate written commercial agreement.",
      "We may suspend or terminate access for violations that create legal, security, or operational risk.",
    ],
  },
  {
    title: "5. Subscription and Billing",
    body: [
      "MyCyber offers subscription tiers and usage limits. Current plans and pricing are available in the billing experience.",
      "Payment processing is handled by Safepay. By subscribing, you authorize recurring charges according to your selected plan cycle and terms.",
      "Refund policy: First-time subscription payments are eligible for refund requests within 7 days, subject to fraud checks and policy compliance.",
      "Subscriptions auto-renew unless cancelled before the next billing cycle. You remain responsible for charges incurred before cancellation becomes effective.",
    ],
  },
  {
    title: "6. Data and Privacy",
    body: [
      "Your use of the service is also governed by our Privacy Policy.",
      "You retain ownership of your data. MyCyber processes data solely to deliver and secure the service and does not claim ownership over customer content.",
      "You are responsible for obtaining all required legal permissions and notices for data you submit.",
    ],
  },
  {
    title: "7. Service Availability",
    body: [
      "MyCyber targets 99% service uptime on a monthly basis, excluding scheduled maintenance, force majeure events, and failures outside our reasonable control.",
      "We may perform maintenance updates to improve reliability and security and will make reasonable efforts to minimize customer impact.",
    ],
  },
  {
    title: "8. Limitation of Liability",
    body: [
      "To the maximum extent permitted by law, MyCyber is not liable for indirect, incidental, special, consequential, or punitive damages, including loss of profits, data, or business interruption.",
      "Our aggregate liability for claims related to the service will not exceed the fees paid by you to MyCyber for the 12 months preceding the claim.",
    ],
  },
  {
    title: "9. Governing Law",
    body: [
      "These Terms are governed by and interpreted under the laws of Pakistan. Any dispute arising out of or relating to these Terms will be subject to the competent courts of Pakistan unless otherwise required by law.",
    ],
  },
  {
    title: "10. Contact",
    body: [
      "For legal questions or notices, contact: legal@mycyber.pk",
      "Company: MyCyber (Feroz Khan), Islamabad, Pakistan",
    ],
  },
];

export default function TermsOfService() {
  return (
    <div className="min-h-screen bg-gray-100 text-gray-900">
      <main className="mx-auto max-w-3xl px-6 py-12 lg:px-8">
        <article className="rounded-2xl border border-gray-200 bg-white p-8 shadow-sm sm:p-10">
          <p className="text-sm font-semibold uppercase tracking-wide text-green-700">
            Terms of Service
          </p>
          <h1 className="mt-2 text-3xl font-bold tracking-tight text-gray-900">
            MyCyber Terms of Service
          </h1>
          <p className="mt-3 text-sm text-gray-600">
            Effective date: January 1, 2025 | Company: MyCyber (Feroz Khan) |
            Islamabad, Pakistan
          </p>

          <p className="mt-6 text-sm text-gray-700">
            Billing details are available via the{" "}
            <Link to="/billing" className="font-semibold text-green-700 hover:text-green-800">
              billing portal
            </Link>
            .
          </p>

          <div className="mt-10 space-y-10 leading-7">
            {sections.map((section) => (
              <section key={section.title}>
                <h2 className="text-xl font-semibold text-gray-900">
                  {section.title}
                </h2>
                <div className="mt-3 space-y-3 text-gray-700">
                  {section.body.map((paragraph) => (
                    <p key={paragraph}>{paragraph}</p>
                  ))}
                </div>
              </section>
            ))}
          </div>
        </article>
      </main>
      <Footer />
    </div>
  );
}
