"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Shield, Menu, X } from "lucide-react";
import { listProfiles, deleteProfile } from "../lib/api";

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

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

const PAGE_SIZE = 6;

export default function ProfilesPage() {
  const router = useRouter();
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [menuOpen, setMenuOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const canvasRef = useRef(null);

  const totalPages = Math.max(1, Math.ceil(profiles.length / PAGE_SIZE));
  const startIndex = (currentPage - 1) * PAGE_SIZE;
  const visibleProfiles = profiles.slice(startIndex, startIndex + PAGE_SIZE);

  useEffect(() => {
    listProfiles()
      .then(setProfiles)
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (currentPage > totalPages) {
      setCurrentPage(totalPages);
    }
  }, [profiles, currentPage, totalPages]);

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
        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975)
          drops[i] = 0;
        drops[i]++;
      }
    };
    const interval = setInterval(draw, 60);

    return () => {
      clearInterval(interval);
      window.removeEventListener("resize", resize);
    };
  }, []);

  const handleDelete = async (id) => {
    if (!confirm("Delete this profile?")) return;
    try {
      await deleteProfile(id);
      setProfiles((prev) => prev.filter((p) => p.id !== id));
    } catch (err) {
      alert("Failed to delete: " + err.message);
    }
  };

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#0a0a0a] text-[#f5f5f5] font-sans">
      <canvas
        ref={canvasRef}
        className="absolute inset-0 w-full h-full opacity-[0.14] pointer-events-none"
      />

      {/* Header */}
      <div className="relative flex items-center gap-4 px-20 pt-7">
        <button onClick={() => setMenuOpen(true)} aria-label="Open menu" className="p-2">
          <Menu size={22} />
        </button>
        <div className="font-mono text-sm tracking-widest text-[#e6e6e6] font-semibold">PRISEC-IV</div>
      </div>

      {/* Title row */}
      <div className="relative flex items-start justify-between px-10 pt-14 pb-10 flex-wrap gap-4 max-w-6xl mx-auto">
        <div>
          <h1
            className="text-5xl font-bold mb-3"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            Device Profiles
          </h1>
          <p className="font-mono text-sm text-[#8a8a8a]">
            {profiles.length} profile{profiles.length !== 1 ? "s" : ""} stored
          </p>
        </div>
        <Link href="/profiles/new">
          <button className="px-5 py-3 rounded-md bg-gradient-to-b from-[#7aa3ff] to-[#4a7bef] text-[#0a0a0a] text-sm font-semibold shadow-lg hover:shadow-[0_6px_22px_rgba(91,140,255,0.55)] transition">
            + New Profile
          </button>
        </Link>
      </div>

      {/* Grid */}
      <div className="relative px-10 pb-8 max-w-6xl mx-auto">
        {loading ? (
          <p className="text-[#8a8a8a] font-mono text-sm">
            Loading profiles...
          </p>
        ) : profiles.length === 0 ? (
          <p className="text-[#8a8a8a] font-mono text-sm">
            No profiles yet — create your first one.
          </p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {visibleProfiles.map((p) => (
              <div
                key={p.id}
                onClick={() => router.push(`/context/${p.id}`)}
                className="group bg-[#121212] border border-white/10 hover:border-[#5b8cff]/60 rounded-2xl p-5 shadow-xl flex flex-col transition-colors duration-200 cursor-pointer"
              >
                <div className="flex items-center justify-between mb-4 gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <Shield size={16} className="text-[#5b8cff] flex-none" />
                    <span className="text-[15px] font-semibold truncate">
                      {p.name}
                    </span>
                  </div>
                  <span className="flex-none text-[10px] font-mono px-2 py-1 rounded-full border border-[#5b8cff]/40 text-[#5b8cff]">
                    {p.detection_method || "manual"}
                  </span>
                </div>

                <div className="flex flex-col gap-2 text-[13px] flex-1">
                  <div className="flex justify-between">
                    <span className="text-[#8a8a8a]">CPU Architecture</span>
                    <span>{p.cpu_architecture}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#8a8a8a]">Clock Speed</span>
                    <span>{formatClockSpeed(p.clock_speed)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#8a8a8a]">Core Count</span>
                    <span>{p.core_count ?? "—"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#8a8a8a]">RAM Capacity</span>
                    <span>{formatRam(p.ram_size)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#8a8a8a]">Battery-powered</span>
                    <span>{p.battery_powered ? "Yes" : "No"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#8a8a8a]">AES-NI Support</span>
                    <span>{p.hw_accel_aes_ni ? "Yes" : "No"}</span>
                  </div>
                </div>

                <div className="border-t border-transparent group-hover:border-white/10 mt-4 pt-3 flex items-center justify-between gap-2 transition-colors duration-200">
                  <span className="font-mono text-[10px] text-[#8a8a8a] truncate">
                    Created {formatDate(p.created_at)}
                  </span>
                  <div className="flex gap-2 flex-none">
                    <Link href={`/profiles/${p.id}/edit`} onClick={(e) => e.stopPropagation()}>
                      <button className="text-xs px-3 py-2 border border-white/15 rounded-md text-[#c7c7c7] hover:bg-white/5 transition">
                        Edit
                      </button>
                    </Link>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDelete(p.id);
                      }}
                      className="text-xs px-3 py-2 border border-white/15 rounded-md text-[#c7c7c7] hover:bg-white/5 transition"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {totalPages > 1 && (
          <div className="flex items-center justify-center gap-2 mt-10">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="px-3 py-2 text-sm border border-white/15 rounded-md text-[#c7c7c7] hover:bg-white/5 transition disabled:opacity-30 disabled:cursor-not-allowed"
            >
              ‹
            </button>

            {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
              <button
                key={page}
                onClick={() => setCurrentPage(page)}
                className={`w-9 h-9 text-sm rounded-md font-mono transition ${
                  page === currentPage
                    ? "bg-gradient-to-b from-[#7aa3ff] to-[#4a7bef] text-[#0a0a0a] font-semibold"
                    : "border border-white/15 text-[#c7c7c7] hover:bg-white/5"
                }`}
              >
                {page}
              </button>
            ))}

            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="px-3 py-2 text-sm border border-white/15 rounded-md text-[#c7c7c7] hover:bg-white/5 transition disabled:opacity-30 disabled:cursor-not-allowed"
            >
              ›
            </button>
          </div>
        )}
      </div>

      {/* Slide-out menu */}
      {menuOpen && (
        <div className="absolute inset-0 z-10">
          <div
            className="absolute inset-0 bg-black/65"
            onClick={() => setMenuOpen(false)}
          />
          <div className="absolute inset-y-0 left-0 w-[280px] bg-[#111] border-r border-white/10 flex flex-col gap-6">
            <div className="flex justify-between items-center px-8 pt-7">
              <span className="font-mono text-xs tracking-widest text-[#5b8cff]">
                PRISEC-IV
              </span>
              <button onClick={() => setMenuOpen(false)}>
                <X size={20} />
              </button>
            </div>
            <nav className="flex flex-col gap-1 px-6">
              <Link
                href="/"
                className="px-2 py-2.5 text-sm font-mono text-[#f5f5f5] rounded transition hover:bg-white/5"
              >
                &gt; Landing Page
              </Link>
              <Link
                href="/profiles"
                className="px-2 py-2.5 text-sm font-mono text-[#5b8cff] rounded transition hover:bg-[#5b8cff]/10"
              >
                &gt; Profiles
              </Link>
              <span className="px-2 py-2.5 text-sm font-mono text-[#f5f5f5] rounded transition hover:bg-white/5 cursor-pointer">
                &gt; Decision Model
              </span>
            </nav>
          </div>
        </div>
      )}
    </div>
  );
}