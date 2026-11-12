//go:build ignore

#include "../../common/bpf_headers/linux_types.h"
#include "../../common/bpf_headers/bpf_endian.h"
#include "../../common/bpf_headers/bpf_helpers.h"

// eBPF map storing the target TCP port to drop.
// Configurable at runtime from userspace without reloading or recompiling the program!
// Key: 0, Value: __u32 port (in host byte order, default: 4040)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} config_port_map SEC(".maps");

// Statistics map:
// Key 0: Total passed packets
// Key 1: Total dropped packets
// Key 2: Total dropped bytes
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} stats_map SEC(".maps");

static __always_inline void increment_stat(__u32 key, __u64 val) {
    __u64 *current_val = bpf_map_lookup_elem(&stats_map, &key);
    if (current_val) {
        __sync_fetch_and_add(current_val, val);
    }
}

SEC("xdp")
int xdp_drop_tcp_port(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Parse Ethernet Header & verify packet boundary
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Only inspect IPv4 traffic
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // 2. Parse IPv4 Header & verify packet boundary
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    // Verify IP header length (IHL >= 5, 20 bytes min)
    if (iph->ihl < 5) {
        return XDP_PASS;
    }

    void *ip_payload = (void *)iph + (iph->ihl * 4);
    if (ip_payload > data_end) {
        return XDP_PASS;
    }

    // Check if the protocol is TCP
    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // 3. Parse TCP Header & verify packet boundary
    struct tcphdr *tcph = ip_payload;
    if ((void *)(tcph + 1) > data_end) {
        return XDP_PASS;
    }

    // 4. Retrieve target port from userspace configurable eBPF map
    __u32 key = 0;
    __u32 *target_port_ptr = bpf_map_lookup_elem(&config_port_map, &key);
    __u16 target_port = 4040; // Default fallback port

    if (target_port_ptr && *target_port_ptr > 0 && *target_port_ptr <= 65535) {
        target_port = (__u16)(*target_port_ptr);
    }

    __u16 dest_port = bpf_ntohs(tcph->dest);
    __u16 src_port = bpf_ntohs(tcph->source);

    // 5. Check if either destination or source matches the target blocked port
    if (dest_port == target_port || src_port == target_port) {
        __u64 pkt_len = (__u64)(data_end - data);
        increment_stat(1, 1);       // Increment dropped packet count
        increment_stat(2, pkt_len); // Increment dropped byte count

        bpf_printk("XDP_DROP: TCP packet matched blocked port %d (src=%d, dst=%d)\n",
                   target_port, src_port, dest_port);

        return XDP_DROP;
    }

    increment_stat(0, 1); // Increment passed packet count
    return XDP_PASS;
}

char _license[] SEC("license") = "Dual MIT/GPL";

