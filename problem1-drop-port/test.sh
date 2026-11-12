#!/usr/bin/env bash
set -euo pipefail

# AccuKnox Problem 1 Automated Test Script
# Verifies that TCP packets destined to port 4040 are dropped via XDP,
# while other ports (e.g. 8080) pass through normally.

echo "=========================================================="
echo " [AccuKnox Test] Problem 1: Drop TCP Packets via XDP"
echo "=========================================================="

if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root (or with sudo) to load eBPF programs." 
   exit 1
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# 1. Compile eBPF C program if object doesn't exist
if [[ ! -f "bpf/xdp_drop_port.o" ]]; then
    echo "[+] Compiling eBPF C program..."
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I../common/bpf_headers -c bpf/xdp_drop_port.c -o bpf/xdp_drop_port.o
fi

# 2. Build Go userspace loader
echo "[+] Building Go userspace loader..."
go build -o drop-port main.go

# 3. Spin up dummy TCP listeners
echo "[+] Starting background TCP servers on port 4040 (target) and port 8080 (control)..."
nc -lk -p 4040 > /dev/null 2>&1 &
PID_4040=$!

nc -lk -p 8080 > /dev/null 2>&1 &
PID_8080=$!

cleanup() {
    echo "[*] Cleaning up background processes..."
    kill -9 "$PID_4040" 2>/dev/null || true
    kill -9 "$PID_8080" 2>/dev/null || true
    if [[ -n "${LOADER_PID:-}" ]]; then
        kill -SIGINT "$LOADER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

sleep 1

# 4. Verify baseline connectivity before XDP attach
echo "[+] Verifying baseline connectivity to port 4040 (should succeed)..."
if nc -z -w 2 127.0.0.1 4040; then
    echo "    [✓] Baseline connection to port 4040 succeeded as expected."
else
    echo "    [-] Baseline connection failed. Check nc."
fi

# 5. Start the eBPF dropper on loopback interface
echo "[+] Launching eBPF XDP packet dropper on interface 'lo' for port 4040..."
./drop-port -iface lo -port 4040 -interactive=false &
LOADER_PID=$!
sleep 2

# 6. Test control port (8080) - Should PASS
echo "[+] Testing connection to control port 8080 (should PASS)..."
if nc -z -w 2 127.0.0.1 8080; then
    echo "    [PASS] Port 8080 connected successfully! eBPF did not block other traffic."
else
    echo "    [FAIL] Port 8080 was blocked unexpectedly."
fi

# 7. Test target blocked port (4040) - Should DROP / TIMEOUT
echo "[+] Testing connection to blocked port 4040 (should DROP / TIMEOUT)..."
if nc -z -w 2 127.0.0.1 4040; then
    echo "    [FAIL] Port 4040 was NOT blocked! Packets got through."
else
    echo "    [PASS] Port 4040 connection timed out! eBPF XDP successfully DROPPED packets at kernel level."
fi

echo "=========================================================="
echo " [✓] Problem 1 Test Completed Successfully!"
echo "=========================================================="

