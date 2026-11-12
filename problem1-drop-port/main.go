package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	ifaceName := flag.String("iface", "lo", "Network interface to attach XDP program (e.g., lo, eth0)")
	port := flag.Int("port", 4040, "TCP port to drop packets on (default: 4040)")
	objPath := flag.String("obj", "bpf/xdp_drop_port.o", "Path to compiled eBPF ELF object file")
	interactive := flag.Bool("interactive", true, "Allow dynamic port updates from console at runtime")
	flag.Parse()

	log.Printf("[+] AccuKnox eBPF Packet Dropper initializing...")
	log.Printf("[+] Target Interface: %s", *ifaceName)
	log.Printf("[+] Initial Blocked TCP Port: %d", *port)
	log.Printf("[+] eBPF Object File: %s", *objPath)

	// 1. Resolve network interface
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("[-] Failed to find interface %q: %v", *ifaceName, err)
	}

	// 2. Load compiled eBPF ELF object file
	spec, err := ebpf.LoadCollectionSpec(*objPath)
	if err != nil {
		log.Fatalf("[-] Failed to load eBPF collection spec from %s: %v\n    (Make sure you compiled the C code using: make)", *objPath, err)
	}

	// 3. Instantiate the eBPF collection in the kernel
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("[-] Failed to load eBPF collection into kernel: %v\n    (Requires root/CAP_BPF/CAP_NET_ADMIN privileges)", err)
	}
	defer coll.Close()

	// 4. Retrieve maps and program
	prog, ok := coll.Programs["xdp_drop_tcp_port"]
	if !ok {
		log.Fatalf("[-] Program 'xdp_drop_tcp_port' not found in collection")
	}

	configMap, ok := coll.Maps["config_port_map"]
	if !ok {
		log.Fatalf("[-] Map 'config_port_map' not found in collection")
	}

	statsMap, ok := coll.Maps["stats_map"]
	if !ok {
		log.Fatalf("[-] Map 'stats_map' not found in collection")
	}

	// 5. Configure initial port in eBPF map from userspace
	key := uint32(0)
	portVal := uint32(*port)
	if err := configMap.Put(&key, &portVal); err != nil {
		log.Fatalf("[-] Failed to initialize port %d in config map: %v", *port, err)
	}
	log.Printf("[✓] Configured eBPF map key 0 -> Port %d", portVal)

	// 6. Attach XDP program to network interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // Falls back to driver mode if available
	})
	if err != nil {
		log.Fatalf("[-] Failed to attach XDP program to %s: %v", *ifaceName, err)
	}
	defer l.Close()

	log.Printf("[✓] Successfully attached XDP program to interface %s (index %d)", *ifaceName, iface.Index)
	log.Printf("[*] Traffic on TCP port %d is now being silently DROPPED at kernel level!", *port)
	if *interactive {
		log.Println("[*] Interactive Mode: Type a new port number and press ENTER to update dynamically at runtime:")
	}

	// 7. Channel for OS interrupt signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// 8. Ticker to periodically display drop/pass packet statistics
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	// 9. Interactive console reader (optional dynamic userspace update demo)
	inputCh := make(chan int)
	if *interactive {
		go func() {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if newPort, err := strconv.Atoi(line); err == nil && newPort > 0 && newPort <= 65535 {
					inputCh <- newPort
				} else if line != "" {
					fmt.Printf("[!] Invalid port '%s'. Enter a number between 1 and 65535.\n", line)
				}
			}
		}()
	}

	for {
		select {
		case sig := <-sigCh:
			log.Printf("\n[!] Received signal %v. Detaching XDP hook and exiting cleanly...", sig)
			printStats(statsMap)
			return

		case newPort := <-inputCh:
			newPortVal := uint32(newPort)
			if err := configMap.Put(&key, &newPortVal); err != nil {
				log.Printf("[-] Failed to update port in eBPF map: %v", err)
			} else {
				log.Printf("[⚡] DYNAMIC UPDATE: Blocked TCP port updated to %d without recompilation or reload!", newPort)
			}

		case <-ticker.C:
			printStats(statsMap)
		}
	}
}

func printStats(statsMap *ebpf.Map) {
	var passedPkts, droppedPkts, droppedBytes uint64
	k0, k1, k2 := uint32(0), uint32(1), uint32(2)

	_ = statsMap.Lookup(&k0, &passedPkts)
	_ = statsMap.Lookup(&k1, &droppedPkts)
	_ = statsMap.Lookup(&k2, &droppedBytes)

	log.Printf("[STATS] Passed: %d pkts | DROPPED: %d pkts (%d bytes)",
		passedPkts, droppedPkts, droppedBytes)
}

