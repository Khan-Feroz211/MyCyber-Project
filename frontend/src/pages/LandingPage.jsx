import { useRef, useEffect, useState } from "react";
import { motion, useInView, useScroll, useTransform, AnimatePresence } from "framer-motion";
import {
  Globe, ArrowRight, Instagram, Twitter, Shield, Zap, Lock,
  Eye, ChevronDown, ArrowUpRight, Sparkles, Activity
} from "lucide-react";
import AboutSection from "../components/landing/AboutSection";
import FeaturedVideoSection from "../components/landing/FeaturedVideoSection";
import PhilosophySection from "../components/landing/PhilosophySection";
import ServicesSection from "../components/landing/ServicesSection";

/* ── Floating orb background ─────────────────────── */
function Orbs() {
  return (
    <div className="fixed inset-0 pointer-events-none overflow-hidden" style={{ zIndex: 0 }}>
      <div
        className="absolute rounded-full blur-[120px] opacity-20"
        style={{
          width: 600, height: 600,
          background: "radial-gradient(circle, #8b5cf6, transparent 70%)",
          top: "-10%", left: "-5%",
          animation: "float 8s ease-in-out infinite",
        }}
      />
      <div
        className="absolute rounded-full blur-[100px] opacity-15"
        style={{
          width: 400, height: 400,
          background: "radial-gradient(circle, #a78bfa, transparent 70%)",
          top: "30%", right: "-5%",
          animation: "float 11s ease-in-out infinite reverse",
        }}
      />
      <div
        className="absolute rounded-full blur-[80px] opacity-10"
        style={{
          width: 300, height: 300,
          background: "radial-gradient(circle, #7c3aed, transparent 70%)",
          bottom: "20%", left: "30%",
          animation: "float 9s ease-in-out infinite 2s",
        }}
      />
    </div>
  );
}

/* ── Animated grid ────────────────────────────────── */
function GridBackground() {
  return (
    <div
      className="fixed inset-0 pointer-events-none"
      style={{
        zIndex: 0,
        backgroundImage: `
          linear-gradient(rgba(139,92,246,0.04) 1px, transparent 1px),
          linear-gradient(90deg, rgba(139,92,246,0.04) 1px, transparent 1px)
        `,
        backgroundSize: "60px 60px",
        maskImage: "radial-gradient(ellipse 80% 80% at 50% 50%, black 20%, transparent 100%)",
      }}
    />
  );
}

/* ── Hero ─────────────────────────────────────────── */
function HeroSection() {
  const videoRef = useRef(null);
  const [email, setEmail] = useState("");
  const { scrollY } = useScroll();
  const heroY = useTransform(scrollY, [0, 600], [0, -80]);
  const heroOpacity = useTransform(scrollY, [0, 400], [1, 0]);

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;
    video.style.opacity = "0";

    function animateOpacity(el, from, to, duration) {
      let start = null;
      const step = (ts) => {
        if (!start) start = ts;
        const p = Math.min((ts - start) / duration, 1);
        el.style.opacity = String(from + (to - from) * p);
        if (p < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    }

    const onCanPlay = () => video.play().then(() => animateOpacity(video, 0, 1, 600));
    const onTimeUpdate = () => {
      if (video.duration - video.currentTime <= 0.55) animateOpacity(video, parseFloat(video.style.opacity) || 1, 0, 500);
    };
    const onEnded = () => {
      video.style.opacity = "0";
      setTimeout(() => { video.currentTime = 0; video.play().then(() => animateOpacity(video, 0, 1, 600)); }, 100);
    };

    video.addEventListener("canplay", onCanPlay);
    video.addEventListener("timeupdate", onTimeUpdate);
    video.addEventListener("ended", onEnded);
    return () => {
      video.removeEventListener("canplay", onCanPlay);
      video.removeEventListener("timeupdate", onTimeUpdate);
      video.removeEventListener("ended", onEnded);
    };
  }, []);

  const navLinks = ["Features", "Pricing", "About"];
  const stats = [
    { value: "99.9%", label: "Uptime SLA" },
    { value: "40+", label: "DLP Rules" },
    { value: "<4s", label: "Scan Time" },
  ];

  return (
    <section className="relative min-h-screen overflow-hidden flex flex-col" style={{ background: "linear-gradient(160deg,#08020f,#0d0520 60%,#07010e)" }}>
      {/* Video bg */}
      <video
        ref={videoRef}
        src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260405_074625_a81f018a-956b-43fb-9aee-4d1508e30e6a.mp4"
        className="absolute inset-0 w-full h-full object-cover object-bottom"
        style={{ mixBlendMode: "luminosity", opacity: 0 }}
        muted autoPlay playsInline preload="auto"
      />
      {/* Purple overlay */}
      <div className="absolute inset-0" style={{ background: "linear-gradient(160deg,rgba(8,2,15,0.85),rgba(13,5,32,0.75) 50%,rgba(8,2,15,0.9))" }} />
      {/* Bottom fade */}
      <div className="absolute bottom-0 left-0 right-0 h-40" style={{ background: "linear-gradient(to top, #08020f, transparent)" }} />

      {/* Navbar */}
      <motion.nav
        className="relative z-20 px-6 py-6"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
      >
        <div className="liquid-glass rounded-full max-w-5xl mx-auto px-6 py-3 flex items-center justify-between">
          <div className="flex items-center">
            <div className="relative mr-3">
              <Shield size={22} className="text-violet-400" />
              <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-violet-500" style={{ animation: "pulse-glow 2s infinite" }} />
            </div>
            <span className="text-white font-semibold text-lg tracking-tight">MyCyber</span>
            <div className="hidden md:flex items-center gap-8 ml-10">
              {navLinks.map((l) => (
                <a key={l} href="#" className="relative text-white/60 hover:text-white text-sm font-medium transition-colors duration-200 group">
                  {l}
                  <span className="absolute -bottom-0.5 left-0 w-0 h-px bg-violet-400 transition-all duration-300 group-hover:w-full" />
                </a>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-3">
            <a href="/login" className="text-white/70 hover:text-white text-sm font-medium transition-colors">Sign In</a>
            <motion.a
              href="/register"
              className="glow-btn rounded-full px-5 py-2 text-white text-sm font-semibold"
              whileHover={{ scale: 1.04 }}
              whileTap={{ scale: 0.97 }}
            >
              Get Started
            </motion.a>
          </div>
        </div>
      </motion.nav>

      {/* Hero content */}
      <motion.div
        className="relative z-10 flex-1 flex flex-col items-center justify-center px-6 py-12 text-center"
        style={{ y: heroY, opacity: heroOpacity }}
      >
        {/* Badge */}
        <motion.div
          className="inline-flex items-center gap-2 liquid-glass rounded-full px-4 py-2 mb-10"
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          <Sparkles size={13} className="text-violet-400" />
          <span className="text-violet-300 text-xs font-medium tracking-widest uppercase">AI-Powered Data Protection</span>
          <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse" />
        </motion.div>

        {/* Heading */}
        <div className="overflow-hidden mb-6">
          <motion.h1
            className="text-6xl md:text-8xl lg:text-9xl text-white tracking-tight whitespace-nowrap"
            style={{ fontFamily: "'Instrument Serif', serif" }}
            initial={{ opacity: 0, y: 60 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.3, ease: [0.22, 1, 0.36, 1] }}
          >
            Secure it{" "}
            <em
              className="italic"
              style={{
                background: "linear-gradient(135deg, #c4b5fd 0%, #a78bfa 40%, #8b5cf6 100%)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
              }}
            >
              all.
            </em>
          </motion.h1>
        </div>

        {/* Subheading */}
        <motion.p
          className="text-white/50 text-base md:text-lg leading-relaxed max-w-xl mb-10"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.5 }}
        >
          Enterprise-grade Data Loss Prevention with real-time threat scanning,
          LLM-aware content filtering, and zero-trust access control.
        </motion.p>

        {/* Email input */}
        <motion.div
          className="max-w-lg w-full mb-6"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.6 }}
        >
          <div className="liquid-glass rounded-full pl-6 pr-2 py-2 flex items-center gap-3">
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="Enter your work email"
              className="flex-1 bg-transparent text-white placeholder:text-white/30 text-sm outline-none"
            />
            <motion.a
              href="/register"
              className="glow-btn rounded-full p-3 text-white"
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.95 }}
            >
              <ArrowRight size={18} />
            </motion.a>
          </div>
        </motion.div>

        {/* Stats row */}
        <motion.div
          className="flex items-center gap-6 md:gap-10 mt-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.7, delay: 0.8 }}
        >
          {stats.map(({ value, label }, i) => (
            <div key={i} className="text-center">
              <p className="text-white text-xl font-bold" style={{ fontFamily: "'Instrument Serif', serif" }}>{value}</p>
              <p className="text-white/40 text-xs mt-0.5">{label}</p>
            </div>
          ))}
        </motion.div>
      </motion.div>

      {/* Feature pills */}
      <motion.div
        className="relative z-10 flex justify-center flex-wrap gap-3 px-6 pb-8"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.7, delay: 1 }}
      >
        {[
          { icon: Shield, label: "Zero-trust Auth" },
          { icon: Zap, label: "Real-time Scanning" },
          { icon: Lock, label: "LLM DLP Pipeline" },
          { icon: Eye, label: "Incident Management" },
          { icon: Activity, label: "Live Alerts" },
        ].map(({ icon: Icon, label }) => (
          <div key={label} className="liquid-glass rounded-full px-4 py-2 flex items-center gap-2">
            <Icon size={13} className="text-violet-400" />
            <span className="text-white/60 text-xs font-medium">{label}</span>
          </div>
        ))}
      </motion.div>

      {/* Social icons */}
      <div className="relative z-10 flex justify-center gap-3 pb-10">
        {[Instagram, Twitter, Globe].map((Icon, i) => (
          <motion.button
            key={i}
            className="liquid-glass rounded-full p-3 text-white/50 hover:text-white transition-colors"
            whileHover={{ scale: 1.1, y: -2 }}
            whileTap={{ scale: 0.95 }}
          >
            <Icon size={18} />
          </motion.button>
        ))}
      </div>

      {/* Scroll cue */}
      <motion.div
        className="absolute bottom-6 left-1/2 -translate-x-1/2 z-10 text-white/30 flex flex-col items-center gap-1"
        animate={{ y: [0, 6, 0] }}
        transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
      >
        <span className="text-xs tracking-widest uppercase">Scroll</span>
        <ChevronDown size={16} />
      </motion.div>
    </section>
  );
}

/* ── Root ─────────────────────────────────────────── */
export default function LandingPage() {
  return (
    <div className="bg-[#08020f] noise">
      <Orbs />
      <GridBackground />
      <div className="relative" style={{ zIndex: 1 }}>
        <HeroSection />
        <AboutSection />
        <FeaturedVideoSection />
        <PhilosophySection />
        <ServicesSection />
      </div>
    </div>
  );
}
