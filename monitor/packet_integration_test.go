//go:build integration
// +build integration

package monitor

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// TestRealNetworkCapture tests packet capture on a real network interface
// This test requires:
// - Root privileges
// - A valid network interface name
// - The interface to be in monitor mode (for WiFi)
//
// Run with: sudo go test -tags=integration -v -run TestRealNetworkCapture
func TestRealNetworkCapture(t *testing.T) {
	ifaceName := os.Getenv("NETWATCH_TEST_IFACE")
	if ifaceName == "" {
		t.Skip("Set NETWATCH_TEST_IFACE environment variable to run this test")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	m, err := NewMonitor(
		OptMonitorDataDir(t.TempDir()),
		OptMonitorQuiet(true),
		OptMonitorStopDur(3*time.Second),
	)
	if err != nil {
		t.Fatalf("NewMonitor() error = %v", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		t.Fatalf("InterfaceByName(%q) error = %v", ifaceName, err)
	}

	monIface := Interface{
		Interface:   *iface,
		Hopper:      NewStaticHopper(),
		HopperIndex: 0,
		HopperTotal: 1,
	}

	// Start listening in a goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- m.Listen(ctx, monIface)
	}()

	// Wait for completion or timeout
	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Listen() error = %v", err)
		}
	case <-ctx.Done():
		// Expected timeout
	}

	// Check aggregate statistics
	m.WithAggregate(func(agg *Aggregate) {
		t.Logf("Packets captured: %d", agg.Global.PacketsTotal)
		t.Logf("Channels seen: %d", len(agg.Channels))
		t.Logf("Sources seen: %d", len(agg.Sources))

		if agg.Global.PacketsTotal == 0 {
			t.Error("capture completed without observing a packet")
		}
		for ch, info := range agg.Channels {
			t.Logf("Channel %d: %d packets (direct: %d, indirect: %d)",
				ch, info.PacketsTotal, info.PacketsDirect, info.PacketsIndirect)
		}
	})
}

// TestRadiotapParsing tests radiotap header parsing on real WiFi packets
// This test requires a WiFi interface in monitor mode
func TestRadiotapParsing(t *testing.T) {
	ifaceName := os.Getenv("NETWATCH_TEST_IFACE")
	if ifaceName == "" {
		t.Skip("Set NETWATCH_TEST_IFACE environment variable to run this test")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	m, err := NewMonitor(
		OptMonitorDataDir(t.TempDir()),
		OptMonitorQuiet(true),
		OptMonitorStopDur(3*time.Second),
	)
	if err != nil {
		t.Fatalf("NewMonitor() error = %v", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		t.Fatalf("InterfaceByName(%q) error = %v", ifaceName, err)
	}

	monIface := Interface{
		Interface:   *iface,
		Hopper:      NewStaticHopper(),
		HopperIndex: 0,
		HopperTotal: 1,
	}

	errChan := make(chan error, 1)
	go func() {
		errChan <- m.Listen(ctx, monIface)
	}()

	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Listen() error = %v", err)
		}
	case <-ctx.Done():
	}

	// Check for radiotap data in aggregate
	m.WithAggregate(func(agg *Aggregate) {
		packetsWithChannel := 0
		packetsWithSignal := 0

		for _, chInfo := range agg.Channels {
			if chInfo.PacketsTotal > 0 {
				packetsWithChannel += chInfo.PacketsTotal
			}
		}

		for _, srcInfo := range agg.Sources {
			if srcInfo.SignalsMean.Len() > 0 {
				packetsWithSignal += srcInfo.Packets
			}
		}

		t.Logf("Packets with channel info: %d", packetsWithChannel)
		t.Logf("Packets with signal info: %d", packetsWithSignal)

		if packetsWithChannel == 0 {
			t.Error("capture completed without channel-bearing radiotap packets")
		}
		if packetsWithSignal == 0 {
			t.Error("capture completed without signal-bearing radiotap packets")
		}
	})
}
