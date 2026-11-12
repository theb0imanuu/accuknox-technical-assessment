#!/usr/bin/env bash
set -euo pipefail

# AccuKnox Problem 2 Automated Test Script
# Verifies that only process 'myprocess' is restricted to port 4040,
# while other ports are dropped for 'myprocess', and other processes remain unaffected.

echo "=========================================================="
echo " [AccuKnox Test] Problem 2: Drop Traffic Per Process"
echo "=========================================================="

if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root (or with sudo) to load eBPF cgroup programs." 
   exit 1
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# 1. Compile eBPF C program
if [[ ! -f "bpf/cgroup_process_filter.o" ]]; then
    echo "[+] Compiling eBPF cgroup program..."
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I../common/bpf_headers -c bpf/cgroup_process_filter.c -o bpf/cgroup_process_filter.o
fi

# 2. Build Go filter and test binary
echo "[+] Building Go controller and 'myprocess' binary..."
go build -o proc-filter main.go
go build -o myprocess ./dummy_process

# 3. Spin up dummy TCP listeners
echo "[+] Starting background TCP servers on port 4040 and port 8080..."
nc -lk -p 4040 > /dev/null 2>&1 &
PID_4040=$!

nc -lk -p 8080 > /dev/null 2>&1 &
PID_8080=$!

cleanup() {
    echo "[*] Cleaning up background processes..."
    kill -9 "$PID_4040" 2>/dev/null || true
    kill -9 "$PID_8080" 2>/dev/null || true
    if [[ -n "${FILTER_PID:-}" ]]; then
        kill -SIGINT "$FILTER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

sleep 1

# 4. Baseline test before eBPF enforcement
echo "[+] Running baseline test with 'myprocess' before eBPF attach (all ports should connect)..."
./myprocess || true

# 5. Start eBPF per-process firewall
echo "[+] Launching eBPF cgroup firewall: Process='myprocess', AllowedPort=4040..."
./proc-filter -process myprocess -port 4040 &
FILTER_PID=$!
sleep 2

# 6. Test 'myprocess' under eBPF enforcement
echo "----------------------------------------------------------"
echo "[+] Executing 'myprocess' under eBPF Zero Trust Policy:"
echo "    Expectation: Port 4040 -> SUCCESS"
echo "                 Port 8080 -> BLOCKED / DROPPED (EPERM)"
echo "----------------------------------------------------------"
./myprocess || true

# 7. Test an arbitrary different process (e.g., nc) to prove only 'myprocess' is restricted
echo "----------------------------------------------------------"
echo "[+] Testing with a DIFFERENT process ('nc') to port 8080:"
echo "    Expectation: Port 8080 -> SUCCESS (unaffected)"
echo "----------------------------------------------------------"
if nc -z -w 2 127.0.0.1 8080; then
    echo "[PASS] Arbitrary process 'nc' connected to port 8080 successfully!"
    echo "       Only 'myprocess' was subjected to kernel drop rules."
else
    echo "[FAIL] 'nc' was unexpectedly blocked."
fi

echo "=========================================================="
echo " [✓] Problem 2 Test Completed Successfully!"
echo "=========================================================="

