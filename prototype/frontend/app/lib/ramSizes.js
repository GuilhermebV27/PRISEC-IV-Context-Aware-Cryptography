// Real memory hardware only ever comes in power-of-2 capacities (256KB, 512KB,
// 1MB, 2MB, ... 4GB, 8GB, ...) - a free-text numeric input lets someone enter
// (or auto-detect produce) an arbitrary decimal that doesn't correspond to any
// real device, which is both meaningless and a source of precision-loss bugs.
// This is a fixed dropdown of standard sizes instead, each stored as an exact
// KB value (all powers of 2, so exact in both binary float and any unit
// conversion - no rounding ambiguity ever).

export const RAM_SIZE_OPTIONS = [
  { label: "1 KB", kb: 1 },
  { label: "2 KB", kb: 2 },
  { label: "4 KB", kb: 4 },
  { label: "8 KB", kb: 8 },
  { label: "16 KB", kb: 16 },
  { label: "32 KB", kb: 32 },
  { label: "64 KB", kb: 64 },
  { label: "128 KB", kb: 128 },
  { label: "256 KB", kb: 256 },
  { label: "512 KB", kb: 512 },
  { label: "1 MB", kb: 1024 },
  { label: "2 MB", kb: 2 * 1024 },
  { label: "4 MB", kb: 4 * 1024 },
  { label: "8 MB", kb: 8 * 1024 },
  { label: "16 MB", kb: 16 * 1024 },
  { label: "32 MB", kb: 32 * 1024 },
  { label: "64 MB", kb: 64 * 1024 },
  { label: "128 MB", kb: 128 * 1024 },
  { label: "256 MB", kb: 256 * 1024 },
  { label: "512 MB", kb: 512 * 1024 },
  { label: "1 GB", kb: 1024 * 1024 },
  { label: "2 GB", kb: 2 * 1024 * 1024 },
  { label: "4 GB", kb: 4 * 1024 * 1024 },
  { label: "8 GB", kb: 8 * 1024 * 1024 },
  { label: "16 GB", kb: 16 * 1024 * 1024 },
  { label: "32 GB", kb: 32 * 1024 * 1024 },
  { label: "64 GB", kb: 64 * 1024 * 1024 },
  { label: "128 GB", kb: 128 * 1024 * 1024 },
];

// ram_size is still sent to the backend as MB (float) - the API contract
// doesn't change, only how the value gets chosen on the frontend.
export function ramKbToMb(kb) {
  return kb / 1024;
}

// For auto-detected specs: the OS reports actual usable memory (e.g.
// 3997.9MB for a "4GB" stick, since some is reserved for hardware/firmware),
// never a clean power of 2. Snap to whichever standard option is closest, so
// auto-detect still lands on a real, storable value instead of the raw noisy
// reading.
export function snapToNearestRamOption(detectedMb) {
  const detectedKb = detectedMb * 1024;
  let closest = RAM_SIZE_OPTIONS[0];
  let closestDiff = Math.abs(detectedKb - closest.kb);
  for (const option of RAM_SIZE_OPTIONS) {
    const diff = Math.abs(detectedKb - option.kb);
    if (diff < closestDiff) {
      closest = option;
      closestDiff = diff;
    }
  }
  return closest;
}