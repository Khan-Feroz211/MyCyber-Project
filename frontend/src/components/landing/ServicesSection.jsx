import { useRef } from "react";
import { motion, useInView } from "framer-motion";
import { ArrowUpRight } from "lucide-react";

const cards = [
  {
    tag: "Detection",
    title: "Scan & Classify",
    description: "We inspect files, text, and prompts for PII, credentials, and policy violations so risk is caught early.",
    video: "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260314_131748_f2ca2a28-fed7-44c8-b9a9-bd9acdd5ec31.mp4",
  },
  {
    tag: "Response",
    title: "Enforce & Remediate",
    description: "We support redaction, alerts, audit trails, and admin actions so teams can respond quickly and consistently.",
    video: "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260324_151826_c7218672-6e92-402c-9e45-f1e0f454bdc4.mp4",
  },
];

export default function ServicesSection() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-100px" });

  return (
    <section
      ref={ref}
      className="py-28 md:py-40 px-6 overflow-hidden"
      style={{ background: "linear-gradient(180deg,#0d0520,#08020f)" }}
    >
      <div className="max-w-6xl mx-auto">
        <motion.div
          className="flex items-center justify-between mb-14"
          initial={{ opacity: 0, y: 30 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.7 }}
        >
          <h2
            className="text-3xl md:text-5xl text-white tracking-tight"
            style={{ fontFamily: "'Instrument Serif', serif" }}
          >
            What MyCyberDLP does
          </h2>
          <p className="text-violet-400/50 text-sm hidden md:block tracking-widest uppercase">Platform capabilities</p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 md:gap-8">
          {cards.map(({ tag, title, description, video }, i) => (
            <motion.div
              key={tag}
              className="glass-card rounded-3xl overflow-hidden group cursor-pointer"
              initial={{ opacity: 0, y: 50 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.8, delay: 0.15 * i, ease: [0.22, 1, 0.36, 1] }}
              whileHover={{ y: -6, transition: { duration: 0.25 } }}
            >
              <div className="relative aspect-video overflow-hidden">
                <video
                  src={video}
                  className="w-full h-full object-cover transition-transform duration-700 group-hover:scale-105"
                  style={{ filter: "hue-rotate(240deg) saturate(0.7) brightness(0.6)" }}
                  muted autoPlay loop playsInline preload="auto"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent" />
                {/* Purple shimmer on hover */}
                <div
                  className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500"
                  style={{ background: "radial-gradient(ellipse at 50% 100%, rgba(139,92,246,0.25), transparent 70%)" }}
                />
              </div>
              <div className="p-6 md:p-8">
                <div className="flex items-start justify-between mb-4">
                  <span
                    className="text-xs tracking-widest uppercase font-medium"
                    style={{ color: "rgba(167,139,250,0.7)" }}
                  >
                    {tag}
                  </span>
                  <motion.div
                    className="liquid-glass rounded-full p-2"
                    whileHover={{ rotate: 45 }}
                    transition={{ duration: 0.2 }}
                  >
                    <ArrowUpRight size={14} className="text-violet-400" />
                  </motion.div>
                </div>
                <h3
                  className="text-white text-xl md:text-2xl mb-3 tracking-tight"
                  style={{ fontFamily: "'Instrument Serif', serif" }}
                >
                  {title}
                </h3>
                <p className="text-white/40 text-sm leading-relaxed">{description}</p>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Footer */}
        <motion.div
          className="mt-24 pt-8 flex flex-col md:flex-row items-center justify-between gap-4"
          style={{ borderTop: "1px solid rgba(139,92,246,0.12)" }}
          initial={{ opacity: 0 }}
          animate={inView ? { opacity: 1 } : {}}
          transition={{ duration: 0.7, delay: 0.5 }}
        >
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-violet-500 animate-pulse" />
            <span className="text-white/30 text-xs">MyCyber DLP Platform — Scanning, policy enforcement, and response</span>
          </div>
          <p className="text-white/20 text-xs">© 2026 MyCyber. All rights reserved.</p>
        </motion.div>
      </div>
    </section>
  );
}
