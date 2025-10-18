//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Including /usr/include/aarch64-linux-gnu due to container.
//
//go:generate go tool bpf2go -tags linux bpf packet_dropper.c -- -I/usr/include/aarch64-linux-gnu
func main() {
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		log.Fatalf("lookup network eth0: %s", err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program to Egress TC.
	l2, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.EgressPacketDropper,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer l2.Close()

	log.Printf("Attached TCx program to EGRESS iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the counters map every second
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s, err := formatCounters(objs.Counters)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("%s\n", s)
	}
}

func formatCounters(countersMap *ebpf.Map) (string, error) {
	var (
		sentCount    uint64
		droppedCount uint64
	)

	// Map keys as in your C code enum
	keySent := uint32(0)
	keyDropped := uint32(1)

	// Lookup PKT_SENT
	if err := countersMap.Lookup(&keySent, &sentCount); err != nil {
		return "", fmt.Errorf("lookup sent counter: %w", err)
	}

	// Lookup PKT_DROPPED
	if err := countersMap.Lookup(&keyDropped, &droppedCount); err != nil {
		return "", fmt.Errorf("lookup dropped counter: %w", err)
	}

	return fmt.Sprintf("Packet Dropper: %10v sent, %10v dropped", sentCount, droppedCount), nil
}
