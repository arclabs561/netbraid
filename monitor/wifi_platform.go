//go:build !linux
// +build !linux

package monitor

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// PlatformWiFi provides platform-specific WiFi operations
type PlatformWiFi interface {
	SetChannel(ctx context.Context, iface string, channel int) error
	GetChannels(ctx context.Context, iface string) ([]int, error)
	SetMonitorMode(ctx context.Context, iface string) error
	IsWiFiInterface(iface string) bool
}

// NewPlatformWiFi creates a platform-specific WiFi implementation
func NewPlatformWiFi() PlatformWiFi {
	switch runtime.GOOS {
	case "darwin":
		// Try to use macOS-specific implementation if available
		// Otherwise fall back to generic macOS implementation
		return &macOSWiFi{}
	case "linux":
		return &linuxWiFi{}
	case "windows":
		return &windowsWiFi{}
	default:
		return &fallbackWiFi{}
	}
}

// macOSWiFi implements WiFi operations for macOS
type macOSWiFi struct{}

func (w *macOSWiFi) SetChannel(ctx context.Context, iface string, channel int) error {
	// macOS uses airport utility for channel control
	// Try to find airport utility
	airportPaths := []string{
		"/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
		"/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport",
		"/usr/local/bin/airport",
		"/opt/homebrew/bin/airport",
	}
	
	var airportPath string
	for _, path := range airportPaths {
		if _, err := exec.LookPath(path); err == nil {
			airportPath = path
			break
		}
	}
	
	if airportPath == "" {
		// Try to find it in PATH
		if path, err := exec.LookPath("airport"); err == nil {
			airportPath = path
		} else {
			return fmt.Errorf("airport utility not found - channel setting not supported on macOS without airport")
		}
	}
	
	// On macOS Sonoma 14.4+, airport is deprecated
	// On macOS 26.1 (Sequoia 15.x), airport is definitely not available
	// Channel setting on macOS is very limited - we can't directly set channels
	// The airport sniff command can capture on specific channels, but that's a different workflow
	
	// Try to use airport to disassociate (may not work on newer macOS)
	cmd := exec.CommandContext(ctx, airportPath, "-z") // Disassociate from networks
	if err := cmd.Run(); err != nil {
		// Airport is likely deprecated - this is expected on macOS 26.1
		return fmt.Errorf("airport utility deprecated on this macOS version - channel setting not supported")
	}
	
	// Even if airport works, direct channel setting isn't possible
	// Channel is determined by the network you're connected to or monitor mode capture
	return fmt.Errorf("direct channel setting not supported on macOS - channels are managed by the system")
}

func (w *macOSWiFi) GetChannels(ctx context.Context, iface string) ([]int, error) {
	// Try to use airport utility if available
	// airport -s shows available networks but not channels directly
	// For now, return common channels
	return []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 40, 44, 48, 149, 153, 157, 161, 165}, nil
}

func (w *macOSWiFi) SetMonitorMode(ctx context.Context, iface string) error {
	// macOS monitor mode is complex and requires special setup
	// For now, just ensure interface is up - we can still capture packets
	// even if not in monitor mode (though we won't see all WiFi traffic)
	cmd := exec.CommandContext(ctx, "ifconfig", iface, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}
	// Note: True monitor mode on macOS requires:
	// 1. Airport utility with -z flag (disconnects from networks)
	// 2. Or using IOKit framework (requires cgo)
	// For now, we'll capture what we can in managed mode
	return nil
}

func (w *macOSWiFi) IsWiFiInterface(iface string) bool {
	// Check if interface is WiFi by checking system_profiler or networksetup
	cmd := exec.Command("networksetup", "-listallhardwareports")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	// Look for WiFi interface in output
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if strings.Contains(line, "Wi-Fi") || strings.Contains(line, "AirPort") {
			// Next line should have device name
			if i+1 < len(lines) {
				if strings.Contains(lines[i+1], "Device: "+iface) {
					return true
				}
			}
		}
	}
	return false
}

// linuxWiFi implements WiFi operations for Linux using iw
type linuxWiFi struct{}

func (w *linuxWiFi) SetChannel(ctx context.Context, iface string, channel int) error {
	if !ValidateChannel(channel) {
		return InvalidChannelError{channel}
	}
	cmd := exec.CommandContext(ctx, "iw", "dev", iface, "set", "channel", fmt.Sprint(channel))
	return cmd.Run()
}

func (w *linuxWiFi) GetChannels(ctx context.Context, iface string) ([]int, error) {
	cmd := exec.CommandContext(ctx, "iw", "list")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	// Parse iw list output to extract channels
	// This is a simplified version - full parsing would use the existing parseWiphyOutput
	return parseChannelsFromIwList(string(out))
}

func (w *linuxWiFi) SetMonitorMode(ctx context.Context, iface string) error {
	// Use existing setMode function logic
	return setMode(ctx, iface)
}

func (w *linuxWiFi) IsWiFiInterface(iface string) bool {
	cmd := exec.Command("iw", "dev", iface, "info")
	return cmd.Run() == nil
}

// windowsWiFi implements WiFi operations for Windows
type windowsWiFi struct{}

func (w *windowsWiFi) SetChannel(ctx context.Context, iface string, channel int) error {
	// Windows doesn't support direct channel setting via command line
	return fmt.Errorf("channel setting not supported on Windows")
}

func (w *windowsWiFi) GetChannels(ctx context.Context, iface string) ([]int, error) {
	// Return common channels
	return []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 40, 44, 48, 149, 153, 157, 161, 165}, nil
}

func (w *windowsWiFi) SetMonitorMode(ctx context.Context, iface string) error {
	// Windows monitor mode requires special drivers (like AirPcap or WinPcap with monitor mode support)
	return fmt.Errorf("monitor mode requires special drivers on Windows")
}

func (w *windowsWiFi) IsWiFiInterface(iface string) bool {
	// Check using netsh
	cmd := exec.Command("netsh", "wlan", "show", "interfaces")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), iface)
}

// fallbackWiFi is a fallback implementation
type fallbackWiFi struct{}

func (w *fallbackWiFi) SetChannel(ctx context.Context, iface string, channel int) error {
	return fmt.Errorf("channel setting not supported on %s", runtime.GOOS)
}

func (w *fallbackWiFi) GetChannels(ctx context.Context, iface string) ([]int, error) {
	// Return common 2.4GHz channels as fallback
	return []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, nil
}

func (w *fallbackWiFi) SetMonitorMode(ctx context.Context, iface string) error {
	return fmt.Errorf("monitor mode not supported on %s", runtime.GOOS)
}

func (w *fallbackWiFi) IsWiFiInterface(iface string) bool {
	return false
}

// parseChannelsFromIwList extracts channel numbers from iw list output
func parseChannelsFromIwList(output string) ([]int, error) {
	var channels []int
	seen := make(map[int]bool)
	
	// Look for channel patterns like "[6]" or "channel 6"
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Match patterns like "* 2437 MHz [6]" or "channel 6"
		if strings.Contains(line, "MHz [") {
			// Extract channel number from [X] pattern
			start := strings.Index(line, "[")
			end := strings.Index(line, "]")
			if start != -1 && end != -1 && end > start {
				chStr := line[start+1 : end]
				var ch int
				if _, err := fmt.Sscanf(chStr, "%d", &ch); err == nil && ch > 0 {
					if !seen[ch] {
						channels = append(channels, ch)
						seen[ch] = true
					}
				}
			}
		}
	}
	
	if len(channels) == 0 {
		// Fallback to common channels
		return []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, nil
	}
	
	return channels, nil
}

