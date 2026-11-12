//go:build ignore

#include "../../common/bpf_headers/linux_types.h"
#include "../../common/bpf_headers/bpf_endian.h"
#include "../../common/bpf_headers/bpf_helpers.h"

#define TASK_COMM_LEN 16

// Configuration rule structure
struct proc_policy {
    char target_process[TASK_COMM_LEN]; // e.g., "myprocess"
    __u32 allowed_port;                 // e.g., 4040 (host byte order)
    __u32 enabled;                      // 1 = active, 0 = disabled
};

// eBPF map storing the per-process network security policy.
// Configurable dynamically from userspace Go at runtime!
// Key: 0, Value: struct proc_policy
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct proc_policy);
    __uint(max_entries, 1);
} policy_map SEC(".maps");

// Audit / Telemetry stats map:
// Key 0: Allowed connections
// Key 1: Blocked/Dropped connections for target process
// Key 2: Unaffected other process connections
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} proc_stats_map SEC(".maps");

static __always_inline void increment_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&proc_stats_map, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

// Verifier-safe string comparison for task comm
static __always_inline int is_same_comm(const char *a, const char *b) {
    #pragma unroll
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
        if (a[i] == '\0') {
            return 1;
        }
    }
    return 1;
}

// BPF program attached to cgroup v2 connect4 hook.
// Fires synchronously inside the process syscall context during connect().
SEC("cgroup/connect4")
int restrict_process_traffic(struct bpf_sock_addr *ctx) {
    // 1. Only enforce on TCP sockets (SOCK_STREAM)
    if (ctx->type != 1 /* SOCK_STREAM */) {
        return 1; // Allow UDP / other protocols
    }

    // 2. Lookup policy configured from userspace
    __u32 key = 0;
    struct proc_policy *policy = bpf_map_lookup_elem(&policy_map, &key);
    if (!policy || policy->enabled == 0) {
        return 1; // Default allow if no policy active
    }

    // 3. Retrieve calling process name (comm) from kernel task_struct
    char current_comm[TASK_COMM_LEN] = {0};
    if (bpf_get_current_comm(&current_comm, sizeof(current_comm)) < 0) {
        return 1;
    }

    // 4. Check if current process matches the target process name
    if (is_same_comm(current_comm, policy->target_process)) {
        // Extract destination port from ctx (user_port is stored in big-endian network byte order)
        __u16 dest_port = bpf_ntohs((__u16)ctx->user_port);
        __u16 allowed_port = (__u16)policy->allowed_port;

        // Policy enforcement:
        // ALLOW ONLY if the destination port matches allowed_port (default: 4040)
        // DROP/DENY all other ports for this specific process!
        if (dest_port == allowed_port) {
            increment_stat(0); // Allowed target process connection
            bpf_printk("[eBPF ALLOW] Process '%s' connecting to permitted port %d\n",
                       current_comm, dest_port);
            return 1; // Allow
        }

        increment_stat(1); // Blocked target process connection
        bpf_printk("[eBPF DROP/DENY] Blocked process '%s' connecting to unauthorized port %d (allowed: %d)\n",
                   current_comm, dest_port, allowed_port);

        // Returning 0 drops the connection and returns -EPERM to the user process syscall
        return 0;
    }

    // 5. All other processes are unaffected and permitted to communicate freely
    increment_stat(2);
    return 1;
}

char _license[] SEC("license") = "Dual MIT/GPL";

