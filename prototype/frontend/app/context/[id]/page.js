"use client";

import { useEffect, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { Shield, Sliders } from "lucide-react";
import { getProfile } from "../../lib/api";

const SECURITY_LEVELS = ["Guest", "Basic", "Advanced", "Admin"];
const CONFIDENTIALITY_LEVELS = ["Low", "Medium", "High"];
const DUTY_CYCLES = ["Continuous", "Periodic", "Sporadic"];
const LATENCY_LEVELS = ["Low", "Medium", "High"];
const DATA_LIFETIME_OPTIONS = [
  "Short-term (session only)",
  "Medium-term (days to weeks)",
  "Long-term archival",
];
const THROUGHPUT_TIERS = [
  { key: "low", label: "Low", score: 0.25 },
  { key: "medium", label: "Medium", score: 0.5 },
  { key: "high", label: "High", score: 0.75 },
  { key: "very_high", label: "Very High", score: 1.0 },
];

function formatClockSpeed(mhz) {
  if (!mhz) return "—";
  if (mhz >= 1000) return `${(mhz / 1000).toFixed(1)} GHz`;
  return `${mhz} MHz`;
}

function formatRam(mb) {
  if (!mb) return "—";
  if (mb >= 1024) return `${(mb / 1024).toFixed(0)} GB`;
  return `${mb} MB`;
}

export default function ContextPage() {
  const { id } = useParams();
  const router = useRouter();
  const canvasRef = useRef(null);

  const [profile, setProfile] = useState(null);
  const [loadingProfile, setLoadingProfile] = useState(true);
  const [result, setResult] = useState({
    cipher: "AES-256-GCM",
    explanation: "Advanced security and high confidentiality call for a well-vetted, hardware-accelerated AEAD cipher.",
  });
  const [matchesDevice, setMatchesDevice] = useState(null);
  const [runningTest, setRunningTest] = useState(false);

  const [form, setForm] = useState({
    security_level: null,
    packet_size: "",
    packet_unit: "KB",
    data_confidentiality: null,
    throughput_tier: null,
    duty_cycle: null,
    latency_tolerance: null,
    data_lifetime: DATA_LIFETIME_OPTIONS[0],
  });

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    getProfile(id)
      .then(setProfile)
      .finally(() => setLoadingProfile(false));
  }, [id]);

  // Matrix background
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

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
  }, [loadingProfile]);

  const update = (field, value) => setForm((prev) => ({ ...prev, [field]: value }));

  const SelectRow = ({ label, required, options, value, onChange }) => (
    <div>
      <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-1.5">
        {label} {required && <span className="text-red-400">*</span>}
      </label>
      <div className="flex gap-3">
        {options.map((opt) => (
          <button
            key={opt}
            type="button"
            onClick={() => onChange(opt)}
            className={`flex-1 py-2.5 rounded-md text-sm font-semibold transition ${
              value === opt
                ? "bg-gradient-to-b from-[#7aa3ff] to-[#4a7bef] text-[#0a0a0a]"
                : "border border-white/15 text-[#c7c7c7] hover:bg-white/5"
            }`}
          >
            {opt}
          </button>
        ))}
      </div>
    </div>
  );

  const handleSubmit = async () => {
    if (
      !form.security_level ||
      !form.packet_size ||
      !form.data_confidentiality ||
      !form.throughput_tier ||
      !form.duty_cycle ||
      !form.latency_tolerance
    ) {
      setError("Please fill in all required fields.");
      return;
    }

    setSaving(true);
    setError(null);
    try {
      const throughputScore = THROUGHPUT_TIERS.find((t) => t.key === form.throughput_tier).score;

      const payload = {
        profile_id: parseInt(id),
        context: {
          security_level: form.security_level,
          packet_size: parseFloat(form.packet_size),
          packet_unit: form.packet_unit,
          data_confidentiality: form.data_confidentiality,
          throughput_tier: form.throughput_tier,
          throughput_score: throughputScore,
          duty_cycle: form.duty_cycle,
          latency_tolerance: form.latency_tolerance,
          data_lifetime: form.data_lifetime,
        },
      };
      const res = await fetch("http://127.0.0.1:8000/decision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error("Failed to run decision model");
      const data = await res.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleRunRealTest = async () => {
    setRunningTest(true);
    try {
      // Call your /execute endpoint here once built
    } finally {
      setRunningTest(false);
    }
  };

  if (loadingProfile) {
    return (
      <div className="min-h-screen bg-[#0a0a0a] text-[#f5f5f5] flex items-center justify-center font-mono text-sm text-[#8a8a8a]">
        Loading profile...
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="min-h-screen bg-[#0a0a0a] text-[#f5f5f5] flex items-center justify-center font-mono text-sm text-[#8a8a8a]">
        Profile not found.
      </div>
    );
  }

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#0a0a0a] text-[#f5f5f5] font-sans">
      <canvas ref={canvasRef} className="absolute inset-0 w-full h-full opacity-[0.14] pointer-events-none" />

      {/* Header */}
      <div className="relative flex items-center justify-between px-20 pt-7">
        <div className="font-mono text-sm tracking-widest text-[#e6e6e6] font-semibold">PRISEC-IV</div>
      </div>

      {/* Two independent columns: left (title+context), right (spacer+result) */}
      <div className="relative px-12 pb-10 flex justify-center">
        <div className="max-w-6xl w-full flex gap-6 items-start">

          {/* LEFT COLUMN */}
          <div className="flex-[1.6] min-w-[500px] flex flex-col">
            <h1
              className="text-5xl font-bold mb-3"
              style={{ fontFamily: "'Space Grotesk', sans-serif" }}
            >
              Set Context
            </h1>
            <p className="font-mono text-sm text-[#8a8a8a] mb-6">
              Describe the deployment so the model can weigh it against the device profile.
            </p>

            <div className="flex items-center justify-between bg-[#121212] border border-white/10 rounded-xl px-5 py-4 mb-8">
              <div className="flex items-center gap-2">
                <Shield size={16} className="text-[#5b8cff]" />
                <span className="text-sm text-[#8a8a8a]">For profile</span>
                <span className="text-sm font-semibold">{profile.name}</span>
              </div>
              <span className="font-mono text-xs text-[#8a8a8a]">
                {profile.cpu_architecture} · {formatClockSpeed(profile.clock_speed)} · {profile.core_count} · {formatRam(profile.ram_size)} · {profile.battery_powered ? "Yes" : "No"} · {profile.hw_accel_aes_ni ? "Yes" : "No"}
              </span>
            </div>

            {/* Context form card */}
            <div className="bg-[#121212] border border-white/10 rounded-2xl p-4 shadow-2xl">
              <div className="flex items-center gap-2 mb-4">
                <Sliders size={18} className="text-[#5b8cff]" />
                <span className="text-[15px] font-semibold">Context Specification</span>
              </div>

              <div className="flex flex-col gap-2.5">
                <SelectRow
                  label="SECURITY LEVEL"
                  required
                  options={SECURITY_LEVELS}
                  value={form.security_level}
                  onChange={(v) => update("security_level", v)}
                />

                <SelectRow
                  label="DATA CONFIDENTIALITY"
                  required
                  options={CONFIDENTIALITY_LEVELS}
                  value={form.data_confidentiality}
                  onChange={(v) => update("data_confidentiality", v)}
                />

                {/* Required Throughput — mandatory, 4-tier scale */}
                <div>
                  <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-1">
                    REQUIRED THROUGHPUT <span className="text-red-400">*</span>
                  </label>
                  <div className="flex gap-2">
                    {THROUGHPUT_TIERS.map((tier) => (
                      <button
                        key={tier.key}
                        type="button"
                        onClick={() => update("throughput_tier", tier.key)}
                        className={`flex-1 py-2.5 rounded-md text-sm font-semibold transition ${
                          form.throughput_tier === tier.key
                            ? "bg-gradient-to-b from-[#7aa3ff] to-[#4a7bef] text-[#0a0a0a]"
                            : "border border-white/15 text-[#c7c7c7] hover:bg-white/5"
                        }`}
                      >
                        {tier.label}
                      </button>
                    ))}
                  </div>
                </div>

                <SelectRow
                  label="DUTY CYCLE"
                  required
                  options={DUTY_CYCLES}
                  value={form.duty_cycle}
                  onChange={(v) => update("duty_cycle", v)}
                />

                <SelectRow
                  label="LATENCY TOLERANCE"
                  required
                  options={LATENCY_LEVELS}
                  value={form.latency_tolerance}
                  onChange={(v) => update("latency_tolerance", v)}
                />

                <div className="grid grid-cols-2 gap-4">
                  <div className="min-w-0">
                    <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-1">
                      DATA LIFETIME <span className="text-red-400">*</span>
                    </label>
                    <select
                      value={form.data_lifetime}
                      onChange={(e) => update("data_lifetime", e.target.value)}
                      className="w-full bg-[#0a0a0a] border border-white/15 rounded-md px-3 py-2.5 text-sm text-[#f5f5f5] focus:outline-none focus:border-[#5b8cff]"
                    >
                      {DATA_LIFETIME_OPTIONS.map((opt) => (
                        <option key={opt} value={opt}>{opt}</option>
                      ))}
                    </select>
                  </div>

                  <div className="min-w-0">
                    <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-1">
                      PACKET SIZE <span className="text-red-400">*</span>
                    </label>
                    <div className="flex gap-1.5">
                      <input
                        type="number"
                        value={form.packet_size}
                        onChange={(e) => update("packet_size", e.target.value)}
                        className="w-0 flex-1 min-w-0 bg-[#0a0a0a] border border-white/15 rounded-md px-3 py-2.5 text-sm focus:outline-none focus:border-[#5b8cff]"
                      />
                      <select
                        value={form.packet_unit}
                        onChange={(e) => update("packet_unit", e.target.value)}
                        className="flex-none w-16 bg-[#0a0a0a] border border-white/15 rounded-md px-2 py-2.5 text-sm text-[#c7c7c7] focus:outline-none focus:border-[#5b8cff]"
                      >
                        <option value="B">B</option>
                        <option value="KB">KB</option>
                        <option value="MB">MB</option>
                      </select>
                    </div>
                  </div>
                </div>
              </div>

              <div className="border-t border-white/10 mt-4 pt-3 flex justify-between items-center">
                <button
                  type="button"
                  onClick={() => router.back()}
                  className="px-5 py-2 border border-white/15 rounded-md text-sm text-[#c7c7c7] hover:bg-white/5 transition"
                >
                  Back
                </button>
                <button
                  type="button"
                  onClick={handleSubmit}
                  disabled={saving}
                  className="px-6 py-2 rounded-md text-sm font-semibold text-[#0a0a0a] bg-gradient-to-b from-[#7aa3ff] to-[#4a7bef] shadow hover:shadow-lg transition disabled:opacity-50"
                >
                  {saving ? "Running..." : "Run Simulation"}
                </button>
              </div>

              {error && <p className="text-red-400 text-sm mt-3">{error}</p>}
            </div>
          </div>

          {/* RIGHT COLUMN */}
          <div className="flex-1 min-w-[320px] flex flex-col">
            <div className="invisible" aria-hidden="true">
              <h1 className="text-5xl font-bold mb-3">Set Context</h1>
              <p className="font-mono text-sm mb-6">placeholder</p>
              <div className="px-5 py-4 mb-8">placeholder</div>
            </div>

            <div className="bg-[#121212] border border-white/10 rounded-2xl p-4 shadow-2xl">
              <div className="flex items-center gap-2 mb-4">
                <Shield size={18} className="text-[#5b8cff]" />
                <span className="text-[15px] font-semibold">Simulation Result</span>
              </div>

              <div className="border border-[#5b8cff]/30 bg-[#5b8cff]/[0.06] rounded-lg p-4 mb-5">
                <div className="text-[11px] text-[#5b8cff] mb-1">Recommended Cipher</div>
                <div className="font-mono text-[15px] font-semibold mb-1.5">{result.cipher}</div>
                <div className="text-[12px] text-[#a9a9a9] leading-relaxed">{result.explanation}</div>
              </div>

              <div className="border-t border-white/10 pt-4">
                <p className="text-sm font-semibold mb-1">Test with real encryption</p>
                <p className="text-xs text-[#8a8a8a] leading-relaxed mb-4">
                  Benchmark the recommended cipher for real, on real hardware — only meaningful if this profile's specs match the device running the test.
                </p>

                <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-2">
                  DOES THIS PROFILE MATCH THIS DEVICE?
                </label>
                <div className="flex gap-3 mb-4">
                  <button
                    type="button"
                    onClick={() => setMatchesDevice(true)}
                    className={`flex-1 py-2.5 rounded-md text-sm font-semibold transition ${
                      matchesDevice === true
                        ? "bg-gradient-to-b from-[#7aa3ff] to-[#4a7bef] text-[#0a0a0a]"
                        : "border border-white/15 text-[#c7c7c7] hover:bg-white/5"
                    }`}
                  >
                    Yes
                  </button>
                  <button
                    type="button"
                    onClick={() => setMatchesDevice(false)}
                    className={`flex-1 py-2.5 rounded-md text-sm font-semibold transition ${
                      matchesDevice === false
                        ? "bg-gradient-to-b from-[#7aa3ff] to-[#4a7bef] text-[#0a0a0a]"
                        : "border border-white/15 text-[#c7c7c7] hover:bg-white/5"
                    }`}
                  >
                    No
                  </button>
                </div>

                <button
                  type="button"
                  onClick={handleRunRealTest}
                  disabled={matchesDevice !== true || runningTest}
                  className="w-full py-2.5 rounded-md text-sm font-semibold border border-white/15 text-[#c7c7c7] hover:bg-white/5 transition disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent"
                >
                  {runningTest ? "Running..." : "Run Real Encryption Test"}
                </button>

                {matchesDevice !== true && (
                  <p className="text-[11px] text-red-400/80 mt-2 leading-relaxed">
                    Disabled — the CPU, RAM, and other specs above must match this device's actual hardware before a live benchmark can be meaningful.
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}