"""
hw_detect.py - Cross-platform, cross-architecture hardware capability
detection for the PRISEC-IV backend. Replaces py-cpuinfo entirely.

Import from main.py:
    from hw_detect import detect_hw_aes, detect_simd, best_simd_tier
"""

import platform
import subprocess

# ---------------------------------------------------------------------------
# AES hardware acceleration detection
# ---------------------------------------------------------------------------

def _detect_aes_windows() -> bool:
    import ctypes
    k32 = ctypes.windll.kernel32
    is_arm = "arm" in platform.machine().lower()
    feature = 30 if is_arm else 12  # PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE : PF_AES_INSTRUCTIONS_AVAILABLE
    try:
        return bool(k32.IsProcessorFeaturePresent(feature))
    except Exception:
        return False


def _detect_aes_macos() -> bool:
    try:
        if platform.machine() == "arm64":
            out = subprocess.run(
                ["sysctl", "-n", "hw.optional.arm.FEAT_AES"],
                capture_output=True, text=True, timeout=2,
            )
            return out.stdout.strip() == "1"
        out = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.features"],
            capture_output=True, text=True, timeout=2,
        )
        return "AES" in out.stdout.upper().split()
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _detect_aes_linux() -> bool:
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith(("flags", "Features")):
                    tokens = set(line.split(":", 1)[1].split())
                    return "aes" in tokens
    except FileNotFoundError:
        pass
    return False


def detect_hw_aes() -> bool:
    system = platform.system()
    if system == "Windows":
        return _detect_aes_windows()
    if system == "Darwin":
        return _detect_aes_macos()
    if system == "Linux":
        return _detect_aes_linux()
    return False


# ---------------------------------------------------------------------------
# SIMD tier detection (SSSE3 / AVX2 / AVX-512 on x86, NEON / SVE on ARM)
# ---------------------------------------------------------------------------

_SIMD_KEYS = ("ssse3", "avx2", "avx512", "neon", "sve")


def _empty_simd() -> dict:
    return {k: False for k in _SIMD_KEYS}


def _detect_simd_windows() -> dict:
    import ctypes
    k32 = ctypes.windll.kernel32
    result = _empty_simd()
    is_arm = "arm" in platform.machine().lower()
    try:
        if is_arm:
            result["neon"] = bool(k32.IsProcessorFeaturePresent(29))  # PF_ARM_V8_INSTRUCTIONS_AVAILABLE
        else:
            result["ssse3"] = bool(k32.IsProcessorFeaturePresent(36))
            result["avx2"] = bool(k32.IsProcessorFeaturePresent(40))
            result["avx512"] = bool(k32.IsProcessorFeaturePresent(41))
    except Exception:
        pass
    return result


def _detect_simd_macos() -> dict:
    result = _empty_simd()
    try:
        if platform.machine() == "arm64":
            result["neon"] = True  # mandatory on AArch64 / Apple Silicon
            out = subprocess.run(
                ["sysctl", "-n", "hw.optional.arm.FEAT_SVE"],
                capture_output=True, text=True, timeout=2,
            )
            result["sve"] = out.stdout.strip() == "1"
        else:
            out = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.features"],
                capture_output=True, text=True, timeout=2,
            )
            feats = out.stdout.upper().split()
            result["ssse3"] = "SSSE3" in feats
            result["avx2"] = "AVX2" in feats
            result["avx512"] = any(f.startswith("AVX512") for f in feats)
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return result


def _detect_simd_linux() -> dict:
    result = _empty_simd()
    machine = platform.machine().lower()
    is_x86 = any(x in machine for x in ("x86", "amd64", "i686"))
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith(("flags", "Features")):
                    tokens = set(line.split(":", 1)[1].split())
                    if is_x86:
                        result["ssse3"] = "ssse3" in tokens
                        result["avx2"] = "avx2" in tokens
                        result["avx512"] = "avx512f" in tokens
                    else:
                        result["neon"] = "neon" in tokens or "asimd" in tokens
                        result["sve"] = "sve" in tokens
                    break
    except FileNotFoundError:
        pass
    return result


def detect_simd() -> dict:
    system = platform.system()
    if system == "Windows":
        return _detect_simd_windows()
    if system == "Darwin":
        return _detect_simd_macos()
    if system == "Linux":
        return _detect_simd_linux()
    return _empty_simd()


def best_simd_tier(simd: dict) -> str:
    if simd.get("avx512"):
        return "avx512"
    if simd.get("avx2"):
        return "avx2"
    if simd.get("sve"):
        return "sve"
    if simd.get("ssse3"):
        return "ssse3"
    if simd.get("neon"):
        return "neon"
    return "scalar"
