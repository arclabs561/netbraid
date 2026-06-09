package monitor

import (
	"net"
	"testing"
	"time"
)

func TestNewAggregate(t *testing.T) {
	agg := NewAggregate()
	if agg == nil {
		t.Fatal("NewAggregate() returned nil")
	}
	if agg.Global.PacketsTotal != 0 {
		t.Errorf("PacketsTotal = %d, want 0", agg.Global.PacketsTotal)
	}
	if len(agg.Channels) != 0 {
		t.Errorf("Channels length = %d, want 0", len(agg.Channels))
	}
	if len(agg.Sources) != 0 {
		t.Errorf("Sources length = %d, want 0", len(agg.Sources))
	}
}

func TestAggregate_WithChannel(t *testing.T) {
	agg := NewAggregate()
	channel := 6
	
	var callCount int
	agg.WithChannel(channel, func(info *ChannelInfo) {
		callCount++
		if info.Channel != channel {
			t.Errorf("Channel = %d, want %d", info.Channel, channel)
		}
		if info.Freq == 0 {
			t.Error("Freq should be set")
		}
	})
	
	if callCount != 1 {
		t.Errorf("callback called %d times, want 1", callCount)
	}
	
	// Verify channel was added
	if _, ok := agg.Channels[channel]; !ok {
		t.Errorf("Channel %d not found in aggregate", channel)
	}
	
	// Call again to test idempotency
	agg.WithChannel(channel, func(info *ChannelInfo) {
		callCount++
		info.PacketsTotal = 10
	})
	
	if callCount != 2 {
		t.Errorf("callback called %d times, want 2", callCount)
	}
	if agg.Channels[channel].PacketsTotal != 10 {
		t.Errorf("PacketsTotal = %d, want 10", agg.Channels[channel].PacketsTotal)
	}
}

func TestAggregate_WithInterface(t *testing.T) {
	agg := NewAggregate()
	iface := Interface{
		Interface: net.Interface{Name: "wlan0"},
	}
	
	var callCount int
	agg.WithInterface(iface, func(info *InterfaceInfo) {
		callCount++
		if info.Interface != iface.Name {
			t.Errorf("Interface = %q, want %q", info.Interface, iface.Name)
		}
	})
	
	if callCount != 1 {
		t.Errorf("callback called %d times, want 1", callCount)
	}
	
	// Verify interface was added
	if _, ok := agg.Interfaces[iface.Name]; !ok {
		t.Errorf("Interface %q not found in aggregate", iface.Name)
	}
}

func TestRollMean(t *testing.T) {
	rm := &RollMean{Window: 10}
	
	// Add values
	for i := 1; i <= 5; i++ {
		rm.Add(float64(i))
	}
	
	if rm.Len() != 5 {
		t.Errorf("Len() = %d, want 5", rm.Len())
	}
	
	mean := rm.Get()
	expected := 3.0 // (1+2+3+4+5)/5
	if mean != expected {
		t.Errorf("Get() = %f, want %f", mean, expected)
	}
	
	// Test windowing
	for i := 6; i <= 15; i++ {
		rm.Add(float64(i))
	}
	
	if rm.Len() != 10 {
		t.Errorf("Len() after windowing = %d, want 10", rm.Len())
	}
}

func TestRollStd(t *testing.T) {
	rs := &RollStd{}
	rs.rollMean.Window = 10
	
	// Add values: 1, 2, 3, 4, 5
	for i := 1; i <= 5; i++ {
		rs.Add(float64(i))
	}
	
	std := rs.Get()
	if std < 0 {
		t.Errorf("Get() = %f, want non-negative", std)
	}
	if rs.Len() != 5 {
		t.Errorf("Len() = %d, want 5", rs.Len())
	}
}

func TestChannelInfo(t *testing.T) {
	agg := NewAggregate()
	channel := 6
	
	agg.WithChannel(channel, func(info *ChannelInfo) {
		info.PacketsTotal = 100
		info.PacketsDirect = 80
		info.PacketsIndirect = 20
		info.SamplesDirect = 10
		info.SamplesIndirect = 5
		info.FirstSeenPacket = time.Now()
		info.LastSeenPacket = time.Now()
	})
	
	info := agg.Channels[channel]
	if info.PacketsTotal != 100 {
		t.Errorf("PacketsTotal = %d, want 100", info.PacketsTotal)
	}
	if info.PacketsDirect != 80 {
		t.Errorf("PacketsDirect = %d, want 80", info.PacketsDirect)
	}
	if info.PacketsIndirect != 20 {
		t.Errorf("PacketsIndirect = %d, want 20", info.PacketsIndirect)
	}
}
