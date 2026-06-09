//go:build darwin
// +build darwin

package monitor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// macOSWiFiDarwin provides macOS-specific WiFi operations using wdutil
type macOSWiFiDarwin struct{}

func (w *macOSWiFiDarwin) SetChannel(ctx context.Context, iface string, channel int) error {
	// macOS doesn't support direct channel setting
	// On macOS Sonoma 14.4+, airport is deprecated
	// wdutil doesn't support channel setting either
	// Channels are managed by the system based on network connection
	return fmt.Errorf("channel setting not supported on macOS - channels are system-managed")
}

func (w *macOSWiFiDarwin) GetChannels(ctx context.Context, iface string) ([]int, error) {
	// Try to get channel info from wdutil or system
	// For now, return common channels as fallback
	return []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 40, 44, 48, 149, 153, 157, 161, 165}, nil
}

func (w *macOSWiFiDarwin) SetMonitorMode(ctx context.Context, iface string) error {
	// macOS monitor mode is very limited
	// Just ensure interface is up
	cmd := exec.CommandContext(ctx, "ifconfig", iface, "up")
	return cmd.Run()
}

func (w *macOSWiFiDarwin) IsWiFiInterface(iface string) bool {
	// Check using networksetup
	cmd := exec.Command("networksetup", "-listallhardwareports")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if strings.Contains(line, "Wi-Fi") || strings.Contains(line, "AirPort") {
			if i+1 < len(lines) && strings.Contains(lines[i+1], "Device: "+iface) {
				return true
			}
		}
	}
	return false
}

