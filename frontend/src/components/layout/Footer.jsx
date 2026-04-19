import React from "react";
import { Link } from "react-router-dom";

const FOOTER_COLUMNS = [
  {
    title: "Product",
    links: [
      { label: "Overview", to: "/" },
      { label: "Pricing", to: "/" },
      { label: "Security", to: "/security" },
    ],
  },
  {
    title: "Legal",
    links: [
      { label: "Privacy Policy", to: "/privacy" },
      { label: "Terms of Service", to: "/terms" },
      { label: "Cookie Policy", to: "/privacy" },
    ],
  },
  {
    title: "Support",
    links: [
      { label: "Contact", to: "/contact" },
      { label: "Privacy", to: "/privacy" },
      { label: "Terms", to: "/terms" },
    ],
  },
  {
    title: "Company",
    links: [
      { label: "Home", to: "/" },
      { label: "Contact", to: "/contact" },
      { label: "Security", to: "/security" },
    ],
  },
];

export default function Footer() {
  return (
    <footer className="border-t border-white/10 bg-[#050b12]/90 backdrop-blur">
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 sm:py-14 lg:px-8">
        <div className="mb-10 flex flex-col gap-4 border-b border-white/10 pb-8 md:flex-row md:items-end md:justify-between">
          <div>
            <p className="font-mono-ui text-[11px] uppercase tracking-[0.28em] text-cyan-300/70">MyCyber</p>
            <h2 className="mt-2 max-w-xl text-2xl font-semibold text-white">Security software designed to look credible in front of enterprise buyers.</h2>
          </div>
          <p className="max-w-sm text-sm leading-6 text-slate-400">
            Built for a real launch: product surfaces, clear trust signaling, and a visual system that can scale from trial users to enterprise demos.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-8 text-center sm:grid-cols-2 sm:gap-10 sm:text-left md:grid-cols-4">
          {FOOTER_COLUMNS.map((column) => (
            <div key={column.title}>
              <h3 className="text-sm font-semibold tracking-wide text-white">
                {column.title}
              </h3>
              <ul className="mt-4 space-y-3 text-sm">
                {column.links.map((item) => (
                  <li key={item.label}>
                    <Link
                      to={item.to}
                      className="text-gray-400 transition hover:text-green-300"
                    >
                      {item.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="mt-10 border-t border-white/10 pt-6 text-center text-sm text-slate-500 sm:text-left">
          © 2025 MyCyber. Built in Pakistan.
        </div>
      </div>
    </footer>
  );
}
