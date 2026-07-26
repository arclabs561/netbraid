package monitor

import (
	"fmt"
	"strings"
)

// parseChannelsFromIwList extracts channel numbers from iw list output.
func parseChannelsFromIwList(output string) ([]int, error) {
	var channels []int
	seen := make(map[int]bool)

	// Look for channel patterns such as "* 2437 MHz [6]".
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "MHz [") {
			continue
		}
		start := strings.Index(line, "[")
		end := strings.Index(line, "]")
		if start == -1 || end == -1 || end <= start {
			continue
		}
		var channel int
		if _, err := fmt.Sscanf(line[start+1:end], "%d", &channel); err == nil && channel > 0 {
			if !seen[channel] {
				channels = append(channels, channel)
				seen[channel] = true
			}
		}
	}

	if len(channels) == 0 {
		return []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, nil
	}
	return channels, nil
}
