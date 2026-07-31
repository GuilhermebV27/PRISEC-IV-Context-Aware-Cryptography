"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Shield } from "lucide-react";
import { createProfile } from "../../lib/api";

const CPU_OPTIONS = ["ARM Cortex-M4", "ARM Cortex-M0", "x86", "RISC-V RV32"];

export default function NewProfilePage() {
  const router = useRouter();
  const canvasRef = useRef(null);

  const [form, setForm] = useState({
    cpu_architecture: "ARM Cortex-M4",
    clock_speed: "1.2",
    core_count: "4",
    ram_size: "512",
    battery_powered: true,
    hw_accel_aes_ni: false,
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  // Matrix background (same as landing page)
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

  const update = (field, value) => setForm((prev) => ({ ...prev, [field]: value }));

  const handleSubmit = async () => {
    setSaving(true);
    setError(null);
    try {
      const payload = {
        cpu_architecture: form.cpu_architecture,
        clock_speed: parseFloat(form.clock_speed),
        core_count: parseInt(form.core_count),
        ram_size: parseInt(form.ram_size),
        battery_powered: form.battery_powered,
        hw_accel_aes_ni: form.hw_accel_aes_ni,
      };
      await createProfile(payload);
      router.push("/profiles");
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const ToggleButton = ({ active, onClick, children }) => (
    <button
      type="button"
      onClick={onClick}
      className={`flex-1 py-3 rounded-md text-sm font-semibold transition ${
        active
          ? "bg-gradient-to-b from-[#7aa3ff] to-[#4a7bef] text-[#0a0a0a]"
          : "border border-white/15 text-[#c7c7c7] hover:bg-white/5"
      }`}
    >
      {children}
    </button>
  );

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#0a0a0a] text-[#f5f5f5] font-sans">
      <canvas ref={canvasRef} className="absolute inset-0 w-full h-full opacity-[0.14] pointer-events-none" />

      {/* Header */}
      <div className="relative flex items-center justify-between px-12 pt-7">
        <div className="font-mono text-sm tracking-widest text-[#e6e6e6] font-semibold">PRISEC-IV</div>
      </div>

      {/* Title */}
        <div className="relative px-12 pt-14 max-w-3xl mx-auto">
        <h1 className="text-5xl font-bold mb-3 text-center" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
            Create Device Profile
        </h1>
        <p className="font-mono text-sm text-[#8a8a8a] mb-10 text-center">
            Describe the device so the model can choose a fitting cipher.
        </p>
        </div>

      {/* Form card */}
        <div className="relative px-12 pb-16 flex justify-center">
        <div className="max-w-3xl w-full bg-[#121212] border border-white/10 rounded-2xl p-8 shadow-2xl">
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center gap-2">
              <Shield size={18} className="text-[#5b8cff]" />
              <span className="text-[15px] font-semibold">Device Profile</span>
            </div>
            <button
              type="button"
              className="text-xs font-mono text-[#8a8a8a] border border-white/15 px-3 py-1.5 rounded-md hover:bg-white/5 transition"
            >
              Auto-Detect
            </button>
          </div>

          <div className="grid grid-cols-2 gap-x-10 gap-y-6">
            {/* CPU Architecture */}
            <div>
              <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-2">
                CPU ARCHITECTURE <span className="text-red-400">*</span>
              </label>
              <select
                value={form.cpu_architecture}
                onChange={(e) => update("cpu_architecture", e.target.value)}
                className="w-full bg-[#0a0a0a] border border-white/15 rounded-md px-4 py-3 text-sm text-[#f5f5f5] focus:outline-none focus:border-[#5b8cff]"
              >
                {CPU_OPTIONS.map((opt) => (
                  <option key={opt} value={opt}>{opt}</option>
                ))}
              </select>
            </div>

            {/* Clock Speed */}
            <div>
              <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-2">CLOCK SPEED</label>
              <div className="flex gap-2">
                <input
                  type="number"
                  step="0.1"
                  value={form.clock_speed}
                  onChange={(e) => update("clock_speed", e.target.value)}
                  className="flex-1 bg-[#0a0a0a] border border-white/15 rounded-md px-4 py-3 text-sm focus:outline-none focus:border-[#5b8cff]"
                />
                <span className="flex items-center px-4 text-sm text-[#8a8a8a] border border-white/15 rounded-md">GHz</span>
              </div>
            </div>

            {/* Core Count */}
            <div>
              <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-2">
                CORE COUNT <span className="text-red-400">*</span>
              </label>
              <input
                type="number"
                value={form.core_count}
                onChange={(e) => update("core_count", e.target.value)}
                className="w-full bg-[#0a0a0a] border border-white/15 rounded-md px-4 py-3 text-sm focus:outline-none focus:border-[#5b8cff]"
              />
            </div>

            {/* RAM Capacity */}
            <div>
              <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-2">
                RAM CAPACITY <span className="text-red-400">*</span>
              </label>
              <div className="flex gap-2">
                <input
                  type="number"
                  value={form.ram_size}
                  onChange={(e) => update("ram_size", e.target.value)}
                  className="flex-1 bg-[#0a0a0a] border border-white/15 rounded-md px-4 py-3 text-sm focus:outline-none focus:border-[#5b8cff]"
                />
                <span className="flex items-center px-4 text-sm text-[#8a8a8a] border border-white/15 rounded-md">MB</span>
              </div>
            </div>

            {/* Battery-powered */}
            <div>
              <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-2">
                BATTERY-POWERED <span className="text-red-400">*</span>
              </label>
              <div className="flex gap-3">
                <ToggleButton active={form.battery_powered} onClick={() => update("battery_powered", true)}>Yes</ToggleButton>
                <ToggleButton active={!form.battery_powered} onClick={() => update("battery_powered", false)}>No</ToggleButton>
              </div>
            </div>

            {/* AES-NI Support */}
            <div>
              <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-2">AES-NI SUPPORT</label>
              <div className="flex gap-3">
                <ToggleButton active={form.hw_accel_aes_ni} onClick={() => update("hw_accel_aes_ni", true)}>Yes</ToggleButton>
                <ToggleButton active={!form.hw_accel_aes_ni} onClick={() => update("hw_accel_aes_ni", false)}>No</ToggleButton>
              </div>
            </div>
          </div>

          <div className="border-t border-white/10 mt-8 pt-6 flex justify-between items-center">
            <button
              type="button"
              onClick={() => router.push("/profiles")}
              className="px-5 py-2.5 border border-white/15 rounded-md text-sm text-[#c7c7c7] hover:bg-white/5 transition"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSubmit}
              disabled={saving}
              className="px-6 py-2.5 rounded-md text-sm font-semibold text-[#0a0a0a] bg-gradient-to-b from-[#7aa3ff] to-[#4a7bef] shadow hover:shadow-lg transition disabled:opacity-50"
            >
              {saving ? "Saving..." : "Save Profile"}
            </button>
          </div>

          {error && <p className="text-red-400 text-sm mt-4">{error}</p>}
        </div>
      </div>
    </div>
  );
}