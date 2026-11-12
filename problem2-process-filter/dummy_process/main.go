package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	procName := filepath.Base(os.Args[0])
	fmt.Printf("[myprocess] Running as binary name: %q (PID: %d)\n", procName, os.Getpid())

	// 1. Test connecting to port 4040 (Permitted port)
	testConnection("127.0.0.1:4040", "Permitted Port (4040)")

	// 2. Test connecting to port 8080 (Unauthorized port)
	testConnection("127.0.0.1:8080", "Unauthorized Port (8080)")

	// 3. Test connecting to port 9090 (Another unauthorized port)
	testConnection("127.0.0.1:9090", "Unauthorized Port (9090)")
}

func testConnection(addr string, label string) {
	fmt.Printf("\n--> Attempting TCP connection to %s (%s)...\n", addr, label)
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("    [-] FAILED to connect to %s: %v\n", addr, err)
		return
	}
	defer conn.Close()
	fmt.Printf("    [✓] SUCCESS: Connected to %s!\n", addr)
}

