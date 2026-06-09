package monitor

import (
	"context"
	"net"
	"testing"
)

func TestValidateChannel(t *testing.T) {
	tests := []struct {
		name    string
		channel int
		want    bool
	}{
		{"valid 2.4GHz channel", 6, true},
		{"valid 5GHz channel", 36, true},
		{"valid 6GHz channel", 100, true},
		{"invalid zero", 0, false},
		{"invalid negative", -1, false},
		{"invalid too high", 300, false},
		{"boundary valid", 233, true},
		{"boundary invalid", 234, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateChannel(tt.channel); got != tt.want {
				t.Errorf("ValidateChannel(%d) = %v, want %v", tt.channel, got, tt.want)
			}
		})
	}
}

func TestValidateInterfaceName(t *testing.T) {
	tests := []struct {
		name string
		iface string
		want bool
	}{
		{"valid interface", "wlan0", true},
		{"valid with dash", "wlan-0", true},
		{"valid with underscore", "wlan_0", true},
		{"empty string", "", false},
		{"too long", "thisinterfaceistoolong", false},
		{"invalid character", "wlan@0", false},
		{"invalid space", "wlan 0", false},
		{"valid eth", "eth0", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateInterfaceName(tt.iface); got != tt.want {
				t.Errorf("ValidateInterfaceName(%q) = %v, want %v", tt.iface, got, tt.want)
			}
		})
	}
}

func TestStaticHopper(t *testing.T) {
	// Skip if iw command is not available (e.g., on macOS without wireless tools)
	// This test requires actual system commands, so we'll test the logic separately
	t.Skip("Skipping test that requires 'iw' command - run integration tests instead")
}

func TestUniformHopper(t *testing.T) {
	t.Skip("Skipping test that requires 'iw' command - run integration tests instead")
	hopper := NewUniformHopper()
	ctx := context.Background()
	
	iface := Interface{
		Interface:   net.Interface{Name: "test"},
		Channels:    []int{1, 6, 11},
		HopperIndex: 0,
		HopperTotal: 1,
	}
	
	// Test multiple hops to ensure it uses available channels
	seenChannels := make(map[int]bool)
	for i := 0; i < 10; i++ {
		action, err := hopper.Hop(ctx, iface)
		if err != nil {
			t.Fatalf("Hop() error = %v", err)
		}
		if action == nil {
			t.Fatal("Hop() returned nil action")
		}
		seenChannels[action.Channel] = true
		
		// Verify channel is in the available list
		found := false
		for _, ch := range iface.Channels {
			if ch == action.Channel {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Hop() channel %d not in available channels %v", action.Channel, iface.Channels)
		}
	}
	
	// With 10 hops on 3 channels, we should see at least one channel
	if len(seenChannels) == 0 {
		t.Error("Hop() did not use any channels")
	}
}

func TestUniformHopper_NoChannels(t *testing.T) {
	t.Skip("Skipping test that requires 'iw' command - run integration tests instead")
	hopper := NewUniformHopper()
	ctx := context.Background()
	
	iface := Interface{
		Interface:   net.Interface{Name: "test"},
		Channels:    []int{}, // No channels specified
		HopperIndex: 0,
		HopperTotal: 1,
	}
	
	// Should fall back to default channels
	action, err := hopper.Hop(ctx, iface)
	if err != nil {
		t.Fatalf("Hop() error = %v", err)
	}
	if action == nil {
		t.Fatal("Hop() returned nil action")
	}
	if action.Channel < 1 || action.Channel > 13 {
		t.Errorf("Hop() channel = %d, want 1-13 (default range)", action.Channel)
	}
}

func TestHopObservation(t *testing.T) {
	obs := NewHopObservation()
	// IsZero checks if ChannelPackets is nil, but NewHopObservation initializes it
	// So it's not zero after creation
	if obs.ChannelPackets == nil {
		t.Error("NewHopObservation() should initialize ChannelPackets")
	}
	
	obs.Packets = 5
	obs.ChannelPackets[6] = 3
	obs.ChannelPackets[11] = 2
	
	if obs.IsZero() {
		t.Error("HopObservation with data should not be zero")
	}
	if obs.Packets != 5 {
		t.Errorf("Packets = %d, want 5", obs.Packets)
	}
	if obs.ChannelPackets[6] != 3 {
		t.Errorf("ChannelPackets[6] = %d, want 3", obs.ChannelPackets[6])
	}
	
	// Test zero observation
	zeroObs := HopObservation{}
	if !zeroObs.IsZero() {
		t.Error("Zero HopObservation should be IsZero()")
	}
}

