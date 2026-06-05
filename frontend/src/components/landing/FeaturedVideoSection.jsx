import { useRef } from "react";
import { motion, useInView } from "framer-motion";

export default function FeaturedVideoSection() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-100px" });

  return (
    <section ref={ref} className="pt-6 md:pt-10 pb-20 md:pb-32 px-6 overflow-hidden" style={{ background: "#0a0318" }}>
      <div className="max-w-6xl mx-auto">
        <motion.div
          className="rounded-3xl overflow-hidden relative aspect-video"
          style={{ border: "1px solid rgba(139,92,246,0.2)" }}
          initial={{ opacity: 0, y: 60 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.9, ease: [0.22, 1, 0.36, 1] }}
        >
          <video
            src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260402_054547_9875cfc5-155a-4229-8ec8-b7ba7125cbf8.mp4"
            className="w-full h-full object-cover"
            style={{ filter: "hue-rotate(240deg) saturate(0.8) brightness(0.7)" }}
            muted autoPlay loop playsInline preload="auto"
          />
          <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-black/20 to-transparent" />
          {/* Purple tint overlay */}
          <div className="absolute inset-0" style={{ background: "radial-gradient(ellipse at 50% 100%, rgba(139,92,246,0.2), transparent 70%)" }} />

          <div className="absolute bottom-0 left-0 right-0 p-6 md:p-10 flex flex-col md:flex-row items-end justify-between gap-6">
            <motion.div
              className="glass-card rounded-2xl p-6 md:p-8 max-w-md"
              initial={{ opacity: 0, x: -20 }}
              animate={inView ? { opacity: 1, x: 0 } : {}}
              transition={{ duration: 0.7, delay: 0.4 }}
            >
              <p className="text-violet-400/70 text-xs tracking-widest uppercase mb-3">Our Approach</p>
              <p className="text-white/80 text-sm md:text-base leading-relaxed">
                We inspect content in motion, apply DLP rules in real time, and trigger the right response before sensitive data can escape.
              </p>
            </motion.div>
            <motion.button
              className="glow-btn rounded-full px-8 py-3 text-white text-sm font-semibold"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              initial={{ opacity: 0, x: 20 }}
              animate={inView ? { opacity: 1, x: 0 } : {}}
              transition={{ duration: 0.7, delay: 0.5 }}
            >
              See protection flow
            </motion.button>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
