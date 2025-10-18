//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

char __license[] SEC("license") = "GPL";

// Target IP to allow (big-endian, as network byte order is big-endian)
#define TARGET_IP  __constant_htonl(0x08080808) // 8.8.8.8
// Target TOS (Type of Service) value to allow
#define TARGET_TOS 0xDD

// Return codes for TC egress programs
#define TC_OK   0   // Allow packet
#define TC_SHOT 2   // Drop packet

// Definition the eBPF maps
// Maps keys
enum { PKT_SENT = 0, PKT_DROPPED = 1, COUNTER_MAX };

// Define the eBPF map structure
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, COUNTER_MAX);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

// Increase the
static __always_inline void inc_counter(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&counters, &key);
    if (val) __sync_fetch_and_add(val, 1);
}

SEC("tc")
int egress_packet_dropper(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    // Ensure packet is long enough for Ethernet header
    if ((void*)(eth + 1) > data_end) return TC_SHOT; // Malformed → drop

    // Only process IPv4 packets, allow others
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return TC_OK;

    // Parse IPv4 header
    struct iphdr *ip = data + sizeof(*eth);
    // Ensure packet is long enough for IP header else drop
    if ((void*)(ip + 1) > data_end || (void*)ip + (ip->ihl * 4) > data_end)
        return TC_SHOT; // Malformed → drop

    // Allow packets destined for TARGET_IP or with TARGET_TOS
    if (ip->daddr == TARGET_IP || ip->tos == TARGET_TOS) {
        inc_counter(PKT_SENT);
        return TC_OK;
    }

    // Drop any other packets
    inc_counter(PKT_DROPPED);
    return TC_SHOT;
}
