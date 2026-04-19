import React from "react";
import Footer from "../../components/layout/Footer";

const sections = [
  {
    title: "1. Introduction and Scope",
    body: [
      "This Privacy Policy explains how MyCyber (operated by Feroz Khan), based in Islamabad, Pakistan, collects, uses, protects, and discloses information when you use the MyCyber DLP platform. This policy applies to our website, web application, APIs, and related services.",
      "By using MyCyber, you acknowledge that you have read and understood this Privacy Policy. If you do not agree, you should stop using the service.",
    ],
  },
  {
    title: "2. Information We Collect",
    body: [
      "Account information: We collect account details such as your name, email address, organization name, and authentication credentials metadata needed to provide secure access.",
      "Scan content: Submitted text or file content is processed in memory to produce detection results. Scan content is not stored by default unless you explicitly enable scan history in your account settings.",
      "Usage data: We collect operational data such as scan counts, timestamps, feature usage, and service performance logs to provide, maintain, and improve platform reliability.",
      "Payment information: Payments are processed by Safepay. MyCyber does not store complete payment card data. We receive limited transaction metadata needed for billing records and account status updates.",
    ],
  },
  {
    title: "3. How We Use Your Information",
    body: [
      "We use your information to authenticate users, deliver DLP scanning services, enforce subscription limits, process billing events, monitor service health, prevent fraud and abuse, and communicate important updates.",
      "We may also use aggregated and de-identified usage analytics to improve model quality, platform performance, and user experience without identifying individual users.",
    ],
  },
  {
    title: "4. Data Retention Policy",
    body: [
      "Scan content is not retained by default and is processed then discarded. If scan history is enabled, retained scan artifacts follow your configured retention settings.",
      "Account and profile data is retained while your account remains active and for a limited period afterward where required for legal, audit, and security purposes.",
      "Billing and financial records are retained for at least 7 years to comply with applicable legal, tax, and audit obligations.",
    ],
  },
  {
    title: "5. Data Sharing",
    body: [
      "MyCyber does not sell personal data to third parties.",
      "Safepay receives payment-related information only to process transactions and settlement. We share only what is necessary to complete billing operations.",
      "We do not integrate with third-party advertising networks for behavioral tracking or ad targeting.",
      "We may disclose information when required by applicable law, lawful request, or to protect the rights, safety, and integrity of our service and users.",
    ],
  },
  {
    title: "6. Security Measures",
    body: [
      "MyCyber uses security controls including JWT-based authentication, bcrypt password hashing, and TLS encryption for data in transit.",
      "Platform data is stored in PostgreSQL with tenant isolation controls and role-based access constraints.",
      "Our deployment architecture supports Kubernetes-level controls, including network policies and service segmentation, to reduce lateral risk.",
      "No security system is perfect. We continuously monitor and improve our controls to reduce risk and respond quickly to incidents.",
    ],
  },
  {
    title: "7. Your Rights (GDPR-Aligned)",
    body: [
      "You may request access to personal data we hold about you.",
      "You may request correction or deletion of your data where legally permitted.",
      "You may request a portable copy of your data in a commonly used format.",
      "To exercise these rights, contact us at privacy@mycyber.pk. We may verify your identity before completing requests.",
    ],
  },
  {
    title: "8. Cookie Policy",
    body: [
      "We use minimal cookies and local storage equivalents required for authentication, session continuity, and essential platform functionality.",
      "We do not use invasive third-party advertising cookies. You can manage browser cookie settings, but disabling essential cookies may impact service functionality.",
    ],
  },
  {
    title: "9. Changes to This Policy",
    body: [
      "We may update this Privacy Policy from time to time due to legal, technical, or operational changes. The updated version will be posted on this page with a revised effective date.",
      "Material changes may also be communicated through account notices or email when appropriate.",
    ],
  },
  {
    title: "10. Contact Information",
    body: [
      "MyCyber (Feroz Khan)",
      "Islamabad, Pakistan",
      "Email: privacy@mycyber.pk",
    ],
  },
];

export default function PrivacyPolicy() {
  return (
    <div className="min-h-screen bg-gray-100 text-gray-900">
      <main className="mx-auto max-w-3xl px-6 py-12 lg:px-8">
        <article className="rounded-2xl border border-gray-200 bg-white p-8 shadow-sm sm:p-10">
          <p className="text-sm font-semibold uppercase tracking-wide text-green-700">
            Privacy Policy
          </p>
          <h1 className="mt-2 text-3xl font-bold tracking-tight text-gray-900">
            MyCyber Privacy Policy
          </h1>
          <p className="mt-3 text-sm text-gray-600">
            Effective date: January 1, 2025 | Company: MyCyber (Feroz Khan) |
            Islamabad, Pakistan
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
