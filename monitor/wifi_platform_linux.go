//go:build linux
// +build linux

package monitor

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// PlatformWiFi provides platform-specific WiFi operations for Linux
type PlatformWiFi interface {
	SetChannel(ctx context.Context, iface string, channel int) error
	GetChannels(ctx context.Context, iface string) ([]int, error)
	SetMonitorMode(ctx context.Context, iface string) error
	IsWiFiInterface(iface string) bool
}

// linuxWiFi implements WiFi operations for Linux using iw
type linuxWiFi struct{}

// NewPlatformWiFi creates a Linux-specific WiFi implementation
func NewPlatformWiFi() PlatformWiFi {
	return &linuxWiFi{}
}

func (w *linuxWiFi) SetChannel(ctx context.Context, iface string, channel int) error {
	if !ValidateChannel(channel) {
		return InvalidChannelError{channel}
	}
	if !ValidateInterfaceName(iface) {
		return fmt.Errorf("invalid interface name: %q", iface)
	}
	cmd := exec.CommandContext(ctx, "iw", "dev", iface, "set", "channel", fmt.Sprint(channel))
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 234 {
			return InvalidChannelError{channel}
		}
		return err
	}
	return nil
}

func (w *linuxWiFi) GetChannels(ctx context.Context, iface string) ([]int, error) {
	cmd := exec.CommandContext(ctx, "iw", "list")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	// Use existing parseWiphyOutput logic
	wiphys, err := parseWiphyOutput(string(out))
	if err != nil {
		// Fallback: try to parse channels directly
		return parseChannelsFromIwList(string(out))
	}
	// Find channels for the specific interface
	cmd = exec.CommandContext(ctx, "iw", "dev", iface, "info")
	infoOut, err := cmd.Output()
	if err != nil {
		// Fallback: return all channels from all wiphys
		var allChannels []int
		seen := make(map[int]bool)
		for _, wiphy := range wiphys {
			for _, ch := range wiphy.ChannelInts() {
				if !seen[ch] {
					allChannels = append(allChannels, ch)
					seen[ch] = true
				}
			}
		}
		return allChannels, nil
	}
	// Parse wiphy index from info and get channels
	// Simplified: return channels from first matching wiphy
	for _, wiphy := range wiphys {
		channels := wiphy.ChannelInts()
		if len(channels) > 0 {
			return channels, nil
		}
	}
	// Ultimate fallback
	return []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, nil
}

func (w *linuxWiFi) SetMonitorMode(ctx context.Context, iface string) error {
	cmd := exec.CommandContext(ctx, "ip", "link", "set", iface, "down")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("setting link down failed: %w", err)
	}
	// We are only doing passive monitoring, so there's no reason to set
	// monitor control.
	cmd = exec.CommandContext(ctx, "iw", iface, "set", "monitor", "none")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("setting monitor control failed: %w", err)
	}
	cmd = exec.CommandContext(ctx, "ip", "link", "set", iface, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("setting link up failed: %w", err)
	}
	return nil
}

func (w *linuxWiFi) IsWiFiInterface(iface string) bool {
	cmd := exec.Command("iw", "dev", iface, "info")
	return cmd.Run() == nil
}

