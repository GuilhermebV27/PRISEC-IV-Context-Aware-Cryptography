export const CPU_OPTIONS = [
  "8-bit MCU (AVR/PIC/8051)",
  "16-bit MCU (MSP430/PIC24/RL78)",
  "ARM Cortex-M0",
  "ARM Cortex-M4",
  "RISC-V RV32",
  "Xtensa",
  "ARM Cortex-R",
  "x86",
  "ARM Cortex-A (32-bit)",
  "ARM Cortex-A (64-bit)",
  "RISC-V RV64",
  "x86_64",
  "PowerPC (32-bit)",
  "PowerPC (64-bit)",
  "ARM64",
  "MIPS64",
];

export const ARCH_WIDTH_SCORE = {
  "8-bit MCU (AVR/PIC/8051)":        { width: 8,  score: 1 },
  "16-bit MCU (MSP430/PIC24/RL78)":  { width: 16, score: 2 },
  "ARM Cortex-M0":                   { width: 32, score: 3.5 },
  "ARM Cortex-M4":                   { width: 32, score: 3.5 },
  "RISC-V RV32":                     { width: 32, score: 3.5 },
  "Xtensa":                          { width: 32, score: 3.5 },
  "ARM Cortex-R":                    { width: 32, score: 3.5 },
  "x86":                             { width: 32, score: 3.5 },
  "ARM Cortex-A (32-bit)":           { width: 32, score: 3.5 },
  "ARM Cortex-A (64-bit)":           { width: 64, score: 5.5 },
  "RISC-V RV64":                     { width: 64, score: 5.5 },
  "x86_64":                          { width: 64, score: 5.5 },
  "PowerPC (32-bit)":                { width: 32, score: 3.5 },
  "PowerPC (64-bit)":                { width: 64, score: 5.5 },
  "ARM64":                           { width: 64, score: 5.5 },
  "MIPS64":                          { width: 64, score: 5.5 },
};

const KB = 1024;
const MB = 1024 * KB;
const GB = 1024 * MB;

const TIERS = [
  { tier: "T1", tierScore: 1, widths: [8],     clockMinExMHz: 0,    clockMaxInMHz: 20,   coresMin: 1,  coresMax: 1,        ramMinExBytes: 0,        ramMaxInBytes: 16 * KB },
  { tier: "T2", tierScore: 2, widths: [16],    clockMinExMHz: 20,   clockMaxInMHz: 40,   coresMin: 1,  coresMax: 1,        ramMinExBytes: 16 * KB,  ramMaxInBytes: 64 * KB },
  { tier: "T3", tierScore: 3, widths: [32],    clockMinExMHz: 40,   clockMaxInMHz: 500,  coresMin: 1,  coresMax: 2,        ramMinExBytes: 64 * KB,  ramMaxInBytes: 512 * MB },
  { tier: "T4", tierScore: 4, widths: [32,64], clockMinExMHz: 500,  clockMaxInMHz: 1500, coresMin: 2,  coresMax: 8,        ramMinExBytes: 512 * MB, ramMaxInBytes: 4 * GB },
  { tier: "T5", tierScore: 5, widths: [64],    clockMinExMHz: 1500, clockMaxInMHz: 4000, coresMin: 4,  coresMax: 16,       ramMinExBytes: 4 * GB,   ramMaxInBytes: 32 * GB },
  { tier: "T6", tierScore: 6, widths: [64],    clockMinExMHz: 4000, clockMaxInMHz: Infinity, coresMin: 17, coresMax: Infinity, ramMinExBytes: 32 * GB, ramMaxInBytes: Infinity },
];

function clockMatches(t, clockMHz) { return clockMHz > t.clockMinExMHz && clockMHz <= t.clockMaxInMHz; }
function coresMatch(t, cores)      { return cores >= t.coresMin && cores <= t.coresMax; }
function ramMatches(t, ramBytes)   { return ramBytes > t.ramMinExBytes && ramBytes <= t.ramMaxInBytes; }
function widthMatches(t, width)    { return t.widths.includes(width); }

export function computeDeviceTier(specs) {
  const archEntry = ARCH_WIDTH_SCORE[specs.archOption];
  if (!archEntry) {
    throw new Error(`Unrecognized CPU architecture option: ${specs.archOption}`);
  }

  const clockMHz = specs.clockMHz;
  const ramBytes = specs.ramMB * MB;
  const cores = specs.cores;
  const width = archEntry.width;

  const fullMatches = TIERS.filter(
    (t) => widthMatches(t, width) && clockMatches(t, clockMHz) && coresMatch(t, cores) && ramMatches(t, ramBytes)
  );
  if (fullMatches.length >= 1) {
    const best = fullMatches.reduce((a, b) => (b.tierScore > a.tierScore ? b : a));
    return best.tierScore;
  }

  const A = archEntry.score;

  const clockTier = TIERS.find((t) => clockMatches(t, clockMHz));
  const F = clockTier.tierScore;

  const ramTier = TIERS.find((t) => ramMatches(t, ramBytes));
  const R = ramTier.tierScore;

  const coreCandidates = TIERS.filter((t) => coresMatch(t, cores));
  const C = coreCandidates.length
    ? coreCandidates.reduce((a, b) => (b.tierScore > a.tierScore ? b : a)).tierScore
    : 6;

  const cps = 0.4 * A + 0.2 * F + 0.2 * C + 0.2 * R;

  return Math.min(6, Math.max(1, Math.round(cps)));
}