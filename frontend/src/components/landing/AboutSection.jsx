import { useRef } from "react";
import { motion, useInView } from "framer-motion";
import { Shield, Zap, Lock } from "lucide-react";

const cards = [
  {
    icon: Shield,
    title: "What It Is",
    body: "MyCyber is a full-stack DLP platform with real-time scanning, LLM-aware content filtering, TOTP MFA, scheduled assessments, and admin incident management — all behind zero-trust authentication.",
  },
  {
    icon: Zap,
    title: "Why It Exists",
    body: "Modern organisations expose sensitive data through uploads, LLM prompts, and API calls. Existing tools are fragmented or cloud-only. MyCyber delivers enterprise protection deployable anywhere.",
  },
  {
    icon: Lock,
    title: "Core Goals",
    body: "Prevent data exfiltration before it reaches external endpoints. Detect PII, credentials, and injections in real time. Provide full audit trails, RBAC, and actionable incident reports.",
  },
];

export default function AboutSection() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-100px" });

  return (
    <section
      ref={ref}
      className="relative pt-32 md:pt-44 pb-20 px-6 overflow-hidden"
      style={{ background: "linear-gradient(180deg, #08020f 0%, #0a0318 100%)" }}
    >
      {/* Top fade from hero */}
      <div className="absolute top-0 left-0 right-0 h-32 pointer-events-none" style={{ background: "linear-gradient(to bottom, #08020f, transparent)" }} />

      <div className="max-w-6xl mx-auto">
        <motion.p
          className="text-violet-400/70 text-sm tracking-widest uppercase mb-5 font-medium"
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6 }}
        >
          About MyCyber
        </motion.p>

        <motion.h2
          className="text-4xl md:text-6xl lg:text-7xl text-white leading-[1.1] tracking-tight mb-16"
          style={{ fontFamily: "'Instrument Serif', serif" }}
          initial={{ opacity: 0, y: 40 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.8, delay: 0.1, ease: [0.22, 1, 0.36, 1] }}
        >
          Pioneering{" "}
          <em
            className="italic"
            style={{
              background: "linear-gradient(135deg,#c4b5fd,#8b5cf6)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
            }}
          >
            defence
          </em>{" "}for
          <br className="hidden md:block" />
          minds that{" "}
          <em className="italic" style={{ color: "rgba(167,139,250,0.7)" }}>
            protect, detect, and respond.
          </em>
        </motion.h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {cards.map(({ icon: Icon, title, body }, i) => (
            <motion.div
              key={title}
              className="glass-card rounded-2xl p-7 group"
              initial={{ opacity: 0, y: 50 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.7, delay: 0.2 + i * 0.12, ease: [0.22, 1, 0.36, 1] }}
              whileHover={{ y: -4, transition: { duration: 0.2 } }}
            >
              <div
                className="w-10 h-10 rounded-xl flex items-center justify-center mb-5"
                style={{ background: "rgba(139,92,246,0.15)", border: "1px solid rgba(139,92,246,0.25)" }}
              >
                <Icon size={18} className="text-violet-400" />
              </div>
              <p className="text-white font-semibold mb-3">{title}</p>
              <p className="text-white/50 text-sm leading-relaxed">{body}</p>
              {/* Hover glow */}
              <div
                className="absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
                style={{ background: "radial-gradient(circle at 50% 0%, rgba(139,92,246,0.08), transparent 70%)" }}
              />
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
