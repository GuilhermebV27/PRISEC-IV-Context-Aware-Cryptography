#!/usr/bin/env bash
#
# run_benchmarks.sh - Compiles and runs Phase 1-4 benchmarks in sequence
#
# Usage:
#   chmod +x run_benchmarks.sh
#   ./run_benchmarks.sh
#
# Each phase is compiled fresh, then run to completion before moving to the
# next phase. Console output from each phase is tee'd to its own log file
# AND to the terminal, so you can watch progress live while still having a
# full record saved to disk (useful given how verbose the per-repeat prints
# are - you mentioned earlier you couldn't even copy all the compiler errors,
# so this avoids that problem for run-time output too).
#
# If any phase fails to compile or exits with a non-zero status, the script
# stops immediately (set -e) rather than silently continuing to the next
# phase with a broken/missing binary.

set -e  # stop on first error
set -o pipefail  # make sure tee doesn't hide a non-zero exit code

CFLAGS="-O2 -fno-stack-protector"
# --wrap flags route all malloc/free/realloc/calloc calls through the peak
# tracker in memtrack.h (required, otherwise linking fails)
LIBS="-lcrypto -lm -Wl,--wrap=malloc,--wrap=free,--wrap=realloc,--wrap=calloc"

LOG_DIR="./logs"
mkdir -p "$LOG_DIR"

TOTAL_START=$(date +%s)

compile_and_run () {
    local src="$1"
    local bin="$2"
    local phase_label="$3"
    local log_file="$LOG_DIR/${bin}.log"

    echo ""
    echo "=================================================================="
    echo " ${phase_label}: compiling ${src} -> ${bin}"
    echo "=================================================================="

    if ! gcc $CFLAGS -o "$bin" "$src" $LIBS; then
        echo "!! Compilation FAILED for ${src}. Stopping." >&2
        exit 1
    fi

    echo ""
    echo "=================================================================="
    echo " ${phase_label}: running ./${bin}  (log: ${log_file})"
    echo "=================================================================="

    local phase_start
    phase_start=$(date +%s)

    ./"$bin" 2>&1 | tee "$log_file"

    local phase_end
    phase_end=$(date +%s)
    echo ""
    echo ">> ${phase_label} finished in $((phase_end - phase_start))s. Output CSV should now exist."
}

echo "Starting full benchmark suite (Phases 1-4)..."
echo "Logs will be saved under: ${LOG_DIR}/"

compile_and_run "benchmark1.c" "benchmark1" "PHASE 1 (single-algorithm baseline)"
compile_and_run "benchmark2.c" "benchmark2" "PHASE 2 (ECC + single algorithm)"
compile_and_run "benchmark3.c" "benchmark3" "PHASE 3 (cascade: two algorithms)"
compile_and_run "benchmark4.c" "benchmark4" "PHASE 4 (ECC + cascade: two algorithms)"

TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$((TOTAL_END - TOTAL_START))

echo ""
echo "=================================================================="
echo " ALL PHASES COMPLETE"
echo "=================================================================="
echo "Total elapsed time: ${TOTAL_ELAPSED}s ($((TOTAL_ELAPSED/60))m $((TOTAL_ELAPSED%60))s)"
echo ""
echo "Result files generated (if all phases succeeded):"
for f in phase1_results.csv phase2_results.csv phase3_results.csv phase4_results.csv; do
    if [ -f "$f" ]; then
        lines=$(wc -l < "$f")
        echo "  - $f  (${lines} lines)"
    else
        echo "  - $f  MISSING"
    fi
done
echo ""
echo "Per-phase console logs saved in: ${LOG_DIR}/"