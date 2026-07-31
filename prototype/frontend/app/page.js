"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import {
  Cpu, Gauge, Grid3x3, MemoryStick, BatteryCharging, Lock,
  Shield, Eye, Waves, RotateCw, Timer, Archive, Menu, X,
  Pencil, SlidersHorizontal,
} from "lucide-react";

export default function Home() {
  const [menuOpen, setMenuOpen] = useState(false);
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    const container = canvas.parentElement;
    const chars = "01ABCDEF";
    const fontSize = 14;
    let cols, drops;

    const resize = () => {
      canvas.width = container.offsetWidth;
      canvas.height = container.offsetHeight;
      cols = Math.floor(canvas.width / fontSize);
      drops = new Array(cols).fill(0).map(() => Math.random() * -50);
    };
    resize();
    window.addEventListener("resize", resize);

    const draw = () => {
      ctx.fillStyle = "rgba(10,10,10,0.12)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = `${fontSize}px "JetBrains Mono", monospace`;
      ctx.fillStyle = "#5b8cff";
      for (let i = 0; i < cols; i++) {
        const char = chars[Math.floor(Math.random() * chars.length)];
        ctx.fillText(char, i * fontSize, drops[i] * fontSize);
        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      }
    };
    const interval = setInterval(draw, 60);

    return () => {
      clearInterval(interval);
      window.removeEventListener("resize", resize);
    };
  }, []);

  const profileFields = [
    { icon: Cpu, label: "CPU Architecture", value: "ARM Cortex-M4" },
    { icon: Gauge, label: "Clock Speed", value: "1.2 GHz" },
    { icon: Grid3x3, label: "Core Count", value: "4" },
    { icon: MemoryStick, label: "RAM Capacity", value: "512 MB" },
    { icon: BatteryCharging, label: "Battery-powered", value: "Yes" },
    { icon: Lock, label: "AES-NI Support", value: "No" },
  ];

  const contextFields = [
    { icon: Shield, label: "Security Level", value: "Advanced" },
    { icon: Eye, label: "Data Confidentiality", value: "High" },
    { icon: Waves, label: "Required Throughput", value: "Yes · 2 Mbps" },
    { icon: RotateCw, label: "Duty Cycle", value: "Continuous" },
    { icon: Timer, label: "Latency Tolerance", value: "Low" },
    { icon: Archive, label: "Data Lifetime", value: "Long-term archival" },
  ];

  const steps = [
    { n: "01", title: "open-menu", text: "use the sidebar to jump between overview, encryption model, and the live demo." },
    { n: "02", title: "build-profile", text: "enter device specs manually, or auto-detect CPU, clock speed, RAM, and AES-NI support." },
    { n: "03", title: "set-context", text: "choose security level, confidentiality, throughput, duty cycle, latency, and data lifetime." },
    { n: "04", title: "run-decision", text: "review the cipher the model recommends, and why, for that profile and context." },
  ];

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#0a0a0a] text-[#f5f5f5] font-sans">
      <canvas ref={canvasRef} className="absolute inset-0 w-full h-full opacity-[0.14] pointer-events-none" />

      {/* Header */}
      <div className="relative flex items-center justify-between px-12 pt-7">
        <div className="font-mono text-sm tracking-widest text-[#e6e6e6] font-semibold">PRISEC-IV</div>
        <button onClick={() => setMenuOpen(true)} aria-label="Open menu" className="p-2">
          <Menu size={22} />
        </button>
      </div>

      {/* Hero + Preview */}
      <div className="relative flex gap-10 px-12 pt-16 pb-16 items-start flex-wrap">
        <div className="flex-1 min-w-[340px] max-w-[560px] pt-6">
          <h1 className="text-6xl leading-tight font-bold mb-6" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
            <div>Adaptive</div>
            <div>Encryption</div>
            <div>
              for <span className="text-[#5b8cff]">IoT Devices</span>
            </div>
          </h1>
          <p className="font-mono text-sm text-[#8a8a8a] mb-6">
            MSc Dissertation · Applied Cryptography · IoT Security
          </p>
          <p className="text-[#c7c7c7] text-[15px] leading-relaxed mb-8 max-w-md">
            An adaptive cryptographic decision engine that selects the most
            appropriate algorithm based on device capabilities and contextual
            security requirements.
          </p>
          <div className="flex gap-4">
            <Link href="/profiles/new">
              <button className="px-6 py-3 rounded bg-gradient-to-b from-[#7aa3ff] to-[#4a7bef] text-[#0a0a0a] text-sm font-semibold shadow-lg hover:shadow-[0_6px_22px_rgba(91,140,255,0.55)] transition">
                Create Profile
              </button>
            </Link>
            <Link href="/profiles">
              <button className="px-6 py-3 rounded border border-[#5b8cff]/40 text-[#5b8cff] text-sm font-semibold hover:bg-[#5b8cff]/10 transition">
                View Profiles
              </button>
            </Link>
          </div>
        </div>

        {/* Preview card */}
        <div className="flex-1 min-w-[600px] max-w-[700px] bg-[#121212] border border-white/10 rounded-2xl p-6 shadow-2xl">
          <div className="flex items-center gap-2 mb-5">
            <Shield size={18} className="text-[#5b8cff]" />
            <span className="text-[15px] font-semibold">Profile &amp; Context Preview</span>
          </div>

          <div className="grid grid-cols-2 gap-8">
            <div>
              <div className="font-mono text-[11px] text-[#5b8cff] tracking-wider mb-3">DEVICE PROFILE</div>
              <div className="flex flex-col gap-2.5">
                {profileFields.map(({ icon: Icon, label, value }) => (
                  <div key={label} className="flex items-center justify-between text-[12.5px]">
                    <span className="flex items-center gap-2 text-[#8a8a8a]">
                      <Icon size={14} className="text-[#5b8cff]" /> {label}
                    </span>
                    <span className="text-[#e6e6e6]">{value}</span>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <div className="font-mono text-[11px] text-[#5b8cff] tracking-wider mb-3">CONTEXT</div>
              <div className="flex flex-col gap-2.5">
                {contextFields.map(({ icon: Icon, label, value }) => (
                  <div key={label} className="flex items-center justify-between text-[12.5px]">
                    <span className="flex items-center gap-2 text-[#8a8a8a]">
                      <Icon size={14} className="text-[#5b8cff]" /> {label}
                    </span>
                    <span className="text-[#e6e6e6]">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-5 border border-[#5b8cff]/30 bg-[#5b8cff]/[0.06] rounded-lg p-4">
            <div className="text-[11px] text-[#8a8a8a] mb-1">Recommended Cipher</div>
            <div className="font-mono text-[15px] font-semibold mb-1.5">ChaCha20-Poly1305</div>
            <div className="text-[11.5px] text-[#a9a9a9] leading-relaxed">
              No AES-NI, high confidentiality, and a continuous duty cycle favor a software-efficient AEAD cipher.
            </div>
          </div>

          <div className="mt-4 flex items-center justify-between">
            <div className="flex gap-2.5">
              <button className="flex items-center gap-1.5 text-[12.5px] text-[#8a8a8a] px-3 py-2 border border-white/10 rounded-md hover:bg-white/5 transition">
                <Pencil size={13} /> Edit Profile
              </button>
            
              <button className="flex items-center gap-1.5 text-[12.5px] text-[#8a8a8a] px-3 py-2 border border-white/10 rounded-md hover:bg-white/5 transition">
                <SlidersHorizontal size={13} /> Edit Context
              </button>
            </div>
              <button className="text-[12.5px] font-semibold text-[#0a0a0a] bg-gradient-to-b from-[#7aa3ff] to-[#4a7bef] px-4 py-2 rounded-md shadow hover:shadow-lg transition">
                Run a Simulation
              </button>
          </div>
        </div>
      </div>

{/* How to use */}
<div className="relative px-12 pb-20">
  <div className="max-w-[1400px] mx-auto">
    <div className="font-mono text-sm text-[#5b8cff] tracking-wide mb-8">
      HOW TO USE THIS PROTOTYPE
    </div>

    <div className="grid grid-cols-2 gap-x-16 gap-y-6 max-w-5xl">
      {steps.map((s) => (
        <div key={s.n} className="flex gap-4 text-sm text-[#c7c7c7]">
          <span className="font-mono text-[#5b8cff] min-w-[42px]">
            [{s.n}]
          </span>

          <span className="leading-relaxed">
            <b className="text-[#f5f5f5]">{s.title}</b> — {s.text}
          </span>
        </div>
      ))}
    </div>
  </div>
</div>

      {/* Slide-out menu */}
      {menuOpen && (
        <div className="absolute inset-0 z-10">
          <div className="absolute inset-0 bg-black/65" onClick={() => setMenuOpen(false)} />
          <div className="absolute inset-y-0 left-0 w-[280px] bg-[#111] border-r border-white/10 p-6 flex flex-col gap-6">
            <div className="flex justify-between items-center">
              <span className="font-mono text-xs tracking-widest text-[#5b8cff]">PRISEC-IV</span>
              <button onClick={() => setMenuOpen(false)}><X size={20} /></button>
            </div>
            <nav className="flex flex-col gap-1 flex-1">
              <Link href="/" className="px-2 py-2.5 text-sm font-mono text-[#5b8cff] rounded hover:bg-[#5b8cff]/10">&gt; Landing Page</Link>
              <Link href="/profiles" className="px-2 py-2.5 text-sm font-mono text-[#f5f5f5] rounded hover:bg-white/5">&gt; Profiles</Link>
              <span className="px-2 py-2.5 text-sm font-mono text-[#f5f5f5] rounded hover:bg-white/5 cursor-pointer">&gt; Decision Model</span>
            </nav>
          </div>
        </div>
      )}
    </div>
  );
}