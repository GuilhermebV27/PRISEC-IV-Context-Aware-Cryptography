"use client";

import { useEffect, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { Shield, Pencil } from "lucide-react";
import { getProfile, updateProfile } from "../../../lib/api";
import { computeDeviceTier, CPU_OPTIONS } from "../../../lib/Devicetier";

const SIMD_TIER_OPTIONS = ["avx512", "avx2", "sve", "ssse3", "neon", "scalar"];

const CLOCK_MULTIPLIERS = { kHz: 0.001, MHz: 1, GHz: 1000 }; // → MHz
const RAM_MULTIPLIERS = { kB: 1 / 1024, MB: 1, GB: 1024 }; // → MB

function normalizeClockToMHz(value, unit) {
  return parseFloat(value) * CLOCK_MULTIPLIERS[unit];
}

function normalizeRamToMB(value, unit) {
  return parseFloat(value) * RAM_MULTIPLIERS[unit];
}

function mapDetectedArch(raw) {
  const normalized = raw.toLowerCase();

  if (normalized.includes("x86_64") || normalized === "amd64") return "x86_64";
  if (normalized === "x86" || normalized === "i386" || normalized === "i686") return "x86";

  if (normalized.includes("aarch64") || normalized.includes("arm64")) return "ARM Cortex-A (64-bit)";
  if (normalized.includes("arm")) return "ARM Cortex-A (32-bit)";

  if (normalized.includes("riscv64")) return "RISC-V RV64";
  if (normalized.includes("riscv32") || normalized.includes("riscv")) return "RISC-V RV32";

  if (normalized.includes("ppc64") || normalized.includes("powerpc64")) return "PowerPC (64-bit)";
  if (normalized.includes("ppc") || normalized.includes("powerpc")) return "PowerPC (32-bit)";

  if (normalized.includes("mips64")) return "MIPS64";

  return null;
}

const EMPTY_ISSUES = {
  cpu_architecture: false,
  clock_speed: false,
  core_count: false,
  ram_size: false,
};

export default function EditProfilePage() {
  const { id } = useParams();
  const router = useRouter();
  const canvasRef = useRef(null);

  const [loadingProfile, setLoadingProfile] = useState(true);
  const [originalDetectionMethod, setOriginalDetectionMethod] = useState("manual");

  const [profileName, setProfileName] = useState("");
  const [editingName, setEditingName] = useState(false);
  const [detected, setDetected] = useState(false); // re-detected THIS session
  const [detecting, setDetecting] = useState(false);
  const [detectionIssues, setDetectionIssues] = useState(EMPTY_ISSUES);

  const [form, setForm] = useState({
    cpu_architecture: "",
    clock_speed: "",
    clock_unit: "MHz",
    core_count: "",
    ram_size: "",
    ram_unit: "MB",
    battery_powered: null,
    hw_accel_aes_ni: null,
    hw_accel_simd_presence: null,
    hw_accel_simd_best_tier: "",
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  // Was this profile originally created via auto-detect? If so, the three
  // boolean fields stay locked unless the user re-runs Auto-Detect now.
  const isAutoLocked = originalDetectionMethod === "auto" && !detected;

  // Load existing profile
  useEffect(() => {
    getProfile(id)
      .then((p) => {
        setProfileName(p.name);
        setOriginalDetectionMethod(p.detection_method || "manual");
        setForm({
          cpu_architecture: p.cpu_architecture || "",
          clock_speed: p.clock_speed != null ? String(p.clock_speed) : "",
          clock_unit: "MHz",
          core_count: p.core_count != null ? String(p.core_count) : "",
          ram_size: p.ram_size != null ? String(p.ram_size) : "",
          ram_unit: "MB",
          battery_powered: p.battery_powered,
          hw_accel_aes_ni: p.hw_accel_aes_ni,
          hw_accel_simd_presence: p.hw_accel_simd_presence,
          hw_accel_simd_best_tier: p.hw_accel_simd_best_tier || "",
        });
      })
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

  const clearIssue = (field) => setDetectionIssues((d) => ({ ...d, [field]: false }));

  const handleAutoDetect = async () => {
    setDetecting(true);
    setError(null);
    try {
      const res = await fetch("http://127.0.0.1:8000/detect-specs");
      const specs = await res.json();

      const mappedArch = mapDetectedArch(specs.cpu_architecture);
      const clockDetected = !!specs.clock_speed_mhz;
      const coreDetected = !!specs.core_count;
      const ramDetected = !!specs.ram_size_mb;

      setForm((prev) => ({
        ...prev,
        cpu_architecture: mappedArch || prev.cpu_architecture,
        clock_speed: clockDetected ? String(specs.clock_speed_mhz) : prev.clock_speed,
        clock_unit: "MHz",
        core_count: coreDetected ? String(specs.core_count) : prev.core_count,
        ram_size: ramDetected ? String(specs.ram_size_mb) : prev.ram_size,
        ram_unit: "MB",
        battery_powered: specs.battery_powered,
        hw_accel_aes_ni: specs.hw_accel_aes_ni,
        hw_accel_simd_presence: specs.hw_accel_simd_presence,
        hw_accel_simd_best_tier: specs.hw_accel_simd_best_tier || "scalar",
      }));

      setDetected(true);
      setDetectionIssues({
        cpu_architecture: !mappedArch,
        clock_speed: !clockDetected,
        core_count: !coreDetected,
        ram_size: !ramDetected,
      });

      const missing = [];
      if (!mappedArch) missing.push(`architecture ("${specs.cpu_architecture}" not recognized)`);
      if (!clockDetected) missing.push("clock speed");
      if (!coreDetected) missing.push("core count");
      if (!ramDetected) missing.push("RAM capacity");
      if (missing.length) {
        setError(
          `Couldn't auto-detect: ${missing.join(", ")}. Please fill those in manually — everything else was applied.`,
        );
      }
    } catch (err) {
      setError("Auto-detect failed: " + err.message);
    } finally {
      setDetecting(false);
    }
  };

  const handleSubmit = async () => {
    if (
      !form.cpu_architecture ||
      !form.core_count ||
      !form.ram_size ||
      form.battery_powered === null
    ) {
      setError("Please fill in all required fields.");
      return;
    }

    setSaving(true);
    setError(null);
    try {
      const clock_speed = normalizeClockToMHz(form.clock_speed, form.clock_unit);
      const ram_size = normalizeRamToMB(form.ram_size, form.ram_unit);
      const core_count = parseInt(form.core_count);

      const device_tier = computeDeviceTier({
        archOption: form.cpu_architecture,
        clockMHz: clock_speed,
        cores: core_count,
        ramMB: ram_size,
      });

      const payload = {
        name: profileName,
        detection_method: detected ? "auto" : originalDetectionMethod,
        cpu_architecture: form.cpu_architecture,
        clock_speed,
        core_count,
        ram_size,
        battery_powered: form.battery_powered,
        hw_accel_aes_ni: form.hw_accel_aes_ni === true,
        hw_accel_simd_presence: form.hw_accel_simd_presence === true,
        hw_accel_simd_best_tier:
          form.hw_accel_simd_presence === true ? form.hw_accel_simd_best_tier : "scalar",
        device_tier,
      };
      await updateProfile(id, payload);
      router.push("/profiles");
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const ToggleButton = ({ active, onClick, disabled, children }) => (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`flex-1 py-3 rounded-md text-sm font-semibold transition ${
        active
          ? "bg-gradient-to-b from-[#7aa3ff] to-[#4a7bef] text-[#0a0a0a]"
          : "border border-white/15 text-[#c7c7c7] hover:bg-white/5"
      } ${disabled ? "opacity-50 cursor-not-allowed" : ""}`}
    >
      {children}
    </button>
  );

  if (loadingProfile) {
    return (
      <div className="min-h-screen bg-[#0a0a0a] text-[#f5f5f5] flex items-center justify-center font-mono text-sm text-[#8a8a8a]">
        Loading profile...
      </div>
    );
  }

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
          Edit Device Profile
        </h1>
        <p className="font-mono text-sm text-[#8a8a8a] mb-10 text-center">
          Update the device specs used by the decision model.
        </p>
      </div>

      {/* Form card */}
      <div className="relative px-12 pb-16 flex justify-center">
        <div className="max-w-3xl w-full bg-[#121212] border border-white/10 rounded-2xl p-8 shadow-2xl">
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center gap-2">
              <Shield size={18} className="text-[#5b8cff]" />
              {editingName ? (
                <input
                  autoFocus
                  value={profileName}
                  onChange={(e) => setProfileName(e.target.value)}
                  onBlur={() => setEditingName(false)}
                  onKeyDown={(e) => e.key === "Enter" && setEditingName(false)}
                  className="bg-transparent border-b border-[#5b8cff] text-[15px] font-semibold text-[#f5f5f5] focus:outline-none"
                />
              ) : (
                <span className="text-[15px] font-semibold">{profileName}</span>
              )}
              <button
                type="button"
                onClick={() => setEditingName(true)}
                className="text-[#8a8a8a] hover:text-[#5b8cff] transition"
              >
                <Pencil size={13} />
              </button>
            </div>
            <button
              type="button"
              onClick={handleAutoDetect}
              disabled={detecting || detected}
              className={`flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-md transition ${
                detected
                  ? "border border-[#5b8cff] text-[#5b8cff] cursor-not-allowed"
                  : detecting
                    ? "border border-red-500 text-red-500 cursor-not-allowed"
                    : "border border-white/15 text-[#8a8a8a] hover:bg-white/5"
              }`}
            >
              {detecting && <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />}
              {detected ? "Auto-Detected" : "Auto-Detect"}
            </button>
          </div>

          {isAutoLocked && (
            <p className="text-xs font-mono text-[#8a8a8a] mb-6 -mt-4">
              This profile was auto-detected — Battery-powered, AES-NI, and SIMD Presence are locked.
              Re-run Auto-Detect above to override them, or edit the remaining fields freely.
            </p>
          )}

          <div className="grid grid-cols-2 gap-x-10 gap-y-6">
            {/* CPU Architecture */}
            <div>
              <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-2">
                CPU ARCHITECTURE <span className="text-red-400">*</span>
              </label>
              <select
                value={form.cpu_architecture}
                onChange={(e) => {
                  update("cpu_architecture", e.target.value);
                  clearIssue("cpu_architecture");
                }}
                className={`w-full bg-[#0a0a0a] border rounded-md px-4 py-3 text-sm text-[#f5f5f5] focus:outline-none focus:border-[#5b8cff] ${
                  detectionIssues.cpu_architecture ? "border-red-500" : "border-white/15"
                }`}
              >
                <option value="" disabled>Select CPU architecture</option>
                {CPU_OPTIONS.map((opt) => (
                  <option key={opt} value={opt}>{opt}</option>
                ))}
              </select>
              {detectionIssues.cpu_architecture && (
                <p className="text-[11px] text-red-400 mt-1.5">Couldn't detect — please select manually.</p>
              )}
            </div>

            {/* Clock Speed */}
            <div>
              <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-2">CLOCK SPEED</label>
              <div className="flex gap-2">
                <input
                  type="number"
                  step="0.1"
                  value={form.clock_speed}
                  onChange={(e) => {
                    update("clock_speed", e.target.value);
                    clearIssue("clock_speed");
                  }}
                  className={`flex-1 bg-[#0a0a0a] border rounded-md px-4 py-3 text-sm focus:outline-none focus:border-[#5b8cff] ${
                    detectionIssues.clock_speed ? "border-red-500" : "border-white/15"
                  }`}
                />
                <select
                  value={form.clock_unit}
                  onChange={(e) => update("clock_unit", e.target.value)}
                  className="bg-[#0a0a0a] border border-white/15 rounded-md px-3 py-3 text-sm text-[#c7c7c7] focus:outline-none focus:border-[#5b8cff]"
                >
                  <option value="kHz">kHz</option>
                  <option value="MHz">MHz</option>
                  <option value="GHz">GHz</option>
                </select>
              </div>
              {detectionIssues.clock_speed && (
                <p className="text-[11px] text-red-400 mt-1.5">Couldn't detect — please enter manually.</p>
              )}
            </div>

            {/* Core Count */}
            <div>
              <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-2">
                CORE COUNT <span className="text-red-400">*</span>
              </label>
              <input
                type="number"
                value={form.core_count}
                onChange={(e) => {
                  update("core_count", e.target.value);
                  clearIssue("core_count");
                }}
                className={`w-full bg-[#0a0a0a] border rounded-md px-4 py-3 text-sm focus:outline-none focus:border-[#5b8cff] ${
                  detectionIssues.core_count ? "border-red-500" : "border-white/15"
                }`}
              />
              {detectionIssues.core_count && (
                <p className="text-[11px] text-red-400 mt-1.5">Couldn't detect — please enter manually.</p>
              )}
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
                  onChange={(e) => {
                    update("ram_size", e.target.value);
                    clearIssue("ram_size");
                  }}
                  className={`flex-1 bg-[#0a0a0a] border rounded-md px-4 py-3 text-sm focus:outline-none focus:border-[#5b8cff] ${
                    detectionIssues.ram_size ? "border-red-500" : "border-white/15"
                  }`}
                />
                <select
                  value={form.ram_unit}
                  onChange={(e) => update("ram_unit", e.target.value)}
                  className="bg-[#0a0a0a] border border-white/15 rounded-md px-3 py-3 text-sm text-[#c7c7c7] focus:outline-none focus:border-[#5b8cff]"
                >
                  <option value="kB">kB</option>
                  <option value="MB">MB</option>
                  <option value="GB">GB</option>
                </select>
              </div>
              {detectionIssues.ram_size && (
                <p className="text-[11px] text-red-400 mt-1.5">Couldn't detect — please enter manually.</p>
              )}
            </div>

            {/* Battery-powered */}
            <div>
              <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-2">
                BATTERY-POWERED <span className="text-red-400">*</span>
              </label>
              <div className="flex gap-3">
                <ToggleButton
                  active={form.battery_powered === true}
                  onClick={() => update("battery_powered", true)}
                  disabled={isAutoLocked}
                >
                  Yes
                </ToggleButton>
                <ToggleButton
                  active={form.battery_powered === false}
                  onClick={() => update("battery_powered", false)}
                  disabled={isAutoLocked}
                >
                  No
                </ToggleButton>
              </div>
            </div>

            {/* AES-NI Support */}
            <div>
              <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-2">AES-NI SUPPORT</label>
              <div className="flex gap-3">
                <ToggleButton
                  active={form.hw_accel_aes_ni === true}
                  onClick={() => update("hw_accel_aes_ni", true)}
                  disabled={isAutoLocked}
                >
                  Yes
                </ToggleButton>
                <ToggleButton
                  active={form.hw_accel_aes_ni === false}
                  onClick={() => update("hw_accel_aes_ni", false)}
                  disabled={isAutoLocked}
                >
                  No
                </ToggleButton>
              </div>
            </div>

            {/* SIMD Presence */}
            <div>
              <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-2">SIMD PRESENCE</label>
              <div className="flex gap-3">
                <ToggleButton
                  active={form.hw_accel_simd_presence === true}
                  onClick={() => update("hw_accel_simd_presence", true)}
                  disabled={isAutoLocked}
                >
                  Yes
                </ToggleButton>
                <ToggleButton
                  active={form.hw_accel_simd_presence === false}
                  onClick={() => update("hw_accel_simd_presence", false)}
                  disabled={isAutoLocked}
                >
                  No
                </ToggleButton>
              </div>
            </div>

            {/* SIMD Tier */}
            <div>
              <label className="block font-mono text-xs text-[#5b8cff] tracking-wide mb-2">HIGHEST SIMD TIER</label>
              <select
                value={form.hw_accel_simd_best_tier}
                onChange={(e) => update("hw_accel_simd_best_tier", e.target.value)}
                disabled={form.hw_accel_simd_presence !== true}
                className="w-full bg-[#0a0a0a] border border-white/15 rounded-md px-4 py-3 text-sm text-[#f5f5f5] focus:outline-none focus:border-[#5b8cff] disabled:opacity-40"
              >
                <option value="" disabled>Select highest SIMD tier</option>
                {SIMD_TIER_OPTIONS.map((opt) => (
                  <option key={opt} value={opt}>{opt.toUpperCase()}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="border-t border-white/10 mt-8 pt-6 flex justify-between items-center">
            <button
              type="button"
              onClick={() => router.back()}
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
              {saving ? "Updating..." : "Update Profile"}
            </button>
          </div>

          {error && <p className="text-red-400 text-sm mt-4">{error}</p>}
        </div>
      </div>
    </div>
  );
}