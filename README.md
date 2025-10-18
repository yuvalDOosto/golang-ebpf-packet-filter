# ebpf-golang: TC egress packet dropper

A minimal Go + eBPF example that attaches a TC egress program to `eth0` and counts packets. The eBPF program allows IPv4 packets destined for `8.8.8.8` or with TOS `0xDD`, and drops all others. A Go userland program loads/attaches the eBPF object and logs per‑second counters for sent vs. dropped packets.
