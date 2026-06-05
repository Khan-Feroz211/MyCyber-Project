import { useRef } from "react";
import { motion, useInView } from "framer-motion";

export default function PhilosophySection() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-100px" });

  return (
    <section ref={ref} className="py-28 md:py-40 px-6 overflow-hidden" style={{ background: "linear-gradient(180deg,#0a0318,#0d0520)" }}>
      <div className="max-w-6xl mx-auto">
        <motion.h2
          className="text-5xl md:text-7xl lg:text-8xl text-white tracking-tight mb-16 md:mb-24"
          style={{ fontFamily: "'Instrument Serif', serif" }}
          initial={{ opacity: 0, y: 40 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
        >
          Detection{" "}
          <em
            className="italic"
            style={{
              background: "linear-gradient(135deg,#c4b5fd,#8b5cf6)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
            }}
          >
            x
          </em>{" "}
          Protection
        </motion.h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 md:gap-12">
          <motion.div
            className="rounded-3xl overflow-hidden aspect-[4/3]"
            style={{ border: "1px solid rgba(139,92,246,0.2)" }}
            initial={{ opacity: 0, x: -40 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
            transition={{ duration: 0.8, delay: 0.15, ease: [0.22, 1, 0.36, 1] }}
          >
            <video
              src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260307_083826_e938b29f-a43a-41ec-a153-3d4730578ab8.mp4"
              className="w-full h-full object-cover"
              style={{ filter: "hue-rotate(240deg) saturate(0.7) brightness(0.65)" }}
              muted autoPlay loop playsInline preload="auto"
            />
          </motion.div>

          <motion.div
            className="flex flex-col justify-center gap-8"
            initial={{ opacity: 0, x: 40 }}
            animate={inView ? { opacity: 1, x: 0 } : {}}
            transition={{ duration: 0.8, delay: 0.15, ease: [0.22, 1, 0.36, 1] }}
          >
            <div>
              <p className="text-violet-400/60 text-xs tracking-widest uppercase mb-4">Built for DLP teams</p>
              <p className="text-white/60 text-base md:text-lg leading-relaxed">
                MyCyber combines policy-aware scanning, threat detection, and controlled response so sensitive data is identified before it leaves your environment.
              </p>
            </div>
            <div className="w-full h-px" style={{ background: "linear-gradient(90deg, rgba(139,92,246,0.3), transparent)" }} />
            <div>
              <p className="text-violet-400/60 text-xs tracking-widest uppercase mb-4">Vision</p>
              <p className="text-white/60 text-base md:text-lg leading-relaxed">
                Our vision is a practical zero-trust DLP platform that helps teams prevent leaks, reduce risk, and keep security decisions fast, explainable, and auditable.
              </p>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
