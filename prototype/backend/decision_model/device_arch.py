"""
device_arch.py

Maps the CPU_OPTIONS architecture string (stored on the Profile) to its
word size in bits - same mapping as ARCH_WIDTH_SCORE in deviceTier.js /
device-classification-model.md, ported to Python for backend use.
"""

ARCH_WORD_BITS = {
    "8-bit MCU (AVR/PIC/8051)": 8,
    "16-bit MCU (MSP430/PIC24/RL78)": 16,
    "ARM Cortex-M0": 32,
    "ARM Cortex-M4": 32,
    "RISC-V RV32": 32,
    "Xtensa": 32,
    "ARM Cortex-R": 32,
    "x86": 32,
    "ARM Cortex-A (32-bit)": 32,
    "ARM Cortex-A (64-bit)": 64,
    "RISC-V RV64": 64,
    "x86_64": 64,
    "PowerPC (32-bit)": 32,
    "PowerPC (64-bit)": 64,
    "ARM64": 64,
    "MIPS64": 64,
}


def word_bits_for(cpu_architecture: str) -> int:
    bits = ARCH_WORD_BITS.get(cpu_architecture)
    if bits is None:
        raise ValueError(f"Unrecognized CPU architecture: {cpu_architecture!r}")
    return bits
