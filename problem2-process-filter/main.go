package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Policy struct matching C definition:
// struct proc_policy {
//     char target_process[16];
//     __u32 allowed_port;
//     __u32 enabled;
// };
type ProcPolicy struct {
	TargetProcess [16]byte
	AllowedPort   uint32
	Enabled       uint32
}

func main() {
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "Path to cgroup v2 mount directory")
	procName := flag.String("process", "myprocess", "Target process name to restrict")
	port := flag.Int("port", 4040, "Allowed TCP port for the target process (all other ports will be dropped)")
	objPath := flag.String("obj", "bpf/cgroup_process_filter.o", "Path to compiled eBPF ELF object file")
	flag.Parse()

	log.Printf("[+] AccuKnox Per-Process eBPF Firewall initializing...")
	log.Printf("[+] Target Process Name: %q", *procName)
	log.Printf("[+] Exclusively Allowed TCP Port: %d (All other ports DROPPED for %s)", *port, *procName)
	log.Printf("[+] Cgroup v2 Path: %s", *cgroupPath)

	// 1. Load compiled eBPF ELF object file
	spec, err := ebpf.LoadCollectionSpec(*objPath)
	if err != nil {
		log.Fatalf("[-] Failed to load eBPF collection spec from %s: %v\n    (Make sure you run: make)", *objPath, err)
	}

	// 2. Load collection into kernel
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("[-] Failed to load eBPF collection into kernel: %v\n    (Requires root / CAP_BPF privileges & cgroup v2)", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs["restrict_process_traffic"]
	if !ok {
		log.Fatalf("[-] Program 'restrict_process_traffic' not found in collection")
	}

	policyMap, ok := coll.Maps["policy_map"]
	if !ok {
		log.Fatalf("[-] Map 'policy_map' not found in collection")
	}

	procStatsMap, ok := coll.Maps["proc_stats_map"]
	if !ok {
		log.Fatalf("[-] Map 'proc_stats_map' not found in collection")
	}

	// 3. Prepare policy in userspace
	var policy ProcPolicy
	copy(policy.TargetProcess[:], []byte(*procName))
	policy.AllowedPort = uint32(*port)
	policy.Enabled = 1

	key := uint32(0)
	if err := policyMap.Put(&key, &policy); err != nil {
		log.Fatalf("[-] Failed to configure policy map: %v", err)
	}
	log.Printf("[✓] Configured eBPF policy map: process=%q, allowed_port=%d, status=ACTIVE", *procName, *port)

	// 4. Attach eBPF program to cgroup v2 connect4 hook
	cgroupFile, err := os.Open(*cgroupPath)
	if err != nil {
		log.Fatalf("[-] Failed to open cgroup path %s: %v", *cgroupPath, err)
	}
	defer cgroupFile.Close()

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: prog,
	})
	if err != nil {
		log.Fatalf("[-] Failed to attach eBPF program to cgroup: %v", err)
	}
	defer l.Close()

	log.Printf("[✓] Successfully attached eBPF program to cgroup: %s", *cgroupPath)
	log.Printf("[*] Zero Trust Process Enforcement Active:")
	log.Printf("    -> Process %q can ONLY send traffic to port %d", *procName, *port)
    log.Printf("    -> Traffic to ANY OTHER PORT by %q will be DROPPED/BLOCKED (-EPERM)", *procName)
	log.Printf("    -> All other system processes continue unaffected.")

	// 5. Signal handling for graceful detachment
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case sig := <-sigCh:
			log.Printf("\n[!] Received signal %v. Detaching cgroup hook and exiting cleanly...", sig)
			printProcStats(procStatsMap, *procName, *port)
			return

		case <-ticker.C:
			printProcStats(procStatsMap, *procName, *port)
		}
	}
}

func printProcStats(statsMap *ebpf.Map, procName string, allowedPort int) {
	var allowedTarget, blockedTarget, otherProc uint64
	k0, k1, k2 := uint32(0), uint32(1), uint32(2)

	_ = statsMap.Lookup(&k0, &allowedTarget)
	_ = statsMap.Lookup(&k1, &blockedTarget)
	_ = statsMap.Lookup(&k2, &otherProc)

	log.Printf("[STATS] Target '%s' -> Allowed (port %d): %d conn | DROPPED (other ports): %d conn | Other Procs: %d conn",
		procName, allowedPort, allowedTarget, blockedTarget, otherProc)
}

