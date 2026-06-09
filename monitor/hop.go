package monitor

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/arclabs561/netwatch/monitor/netref"
	"github.com/arclabs561/netwatch/sample"
)

type HopperStrategy func() Hopper

type Hopper interface {
	Hop(ctx context.Context, iface Interface) (*HopAction, error)
	Update(iface Interface, action HopAction, obs HopObservation)
}

type HopAction struct {
	Index   int `json:"index"`
	Channel int `json:"channel"`
}

type HopInterval struct{}

type HopObservation struct {
	Packets        int         `json:"packets"`
	ChannelPackets map[int]int `json:"channel_packets"`
}

func (o HopObservation) IsZero() bool {
	return o.ChannelPackets == nil
}

func NewHopObservation() HopObservation {
	return HopObservation{
		ChannelPackets: make(map[int]int),
	}
}

var (
	_ Hopper = (*StaticHopper)(nil)
	_ Hopper = (*UniformHopper)(nil)
	_ Hopper = (*ThompsonSamplingHopper)(nil)
)

func OneshotImmediateSchedule() chan HopInterval {
	ch := make(chan HopInterval)
	go func() {
		ch <- HopInterval{}
		close(ch)
	}()
	return ch
}

func PerpetualFixedIntervalSchedule(
	ctx context.Context,
	dur time.Duration,
) chan HopInterval {
	ch := make(chan HopInterval)
	ticker := time.NewTicker(dur)
	go func() {
		defer close(ch)
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				ch <- HopInterval{}
			}
		}
	}()
	return ch
}

func NewStaticHopper() Hopper {
	return &StaticHopper{}
}

type StaticHopper struct{}

func (h StaticHopper) String() string {
	b, err := h.MarshalText()
	if err != nil {
		return fmt.Sprintf("invalid(%#v: %v)", h, err)
	}
	return string(b)
}

func (h StaticHopper) MarshalText() ([]byte, error) {
	return []byte("static"), nil
}

func (h *StaticHopper) Hop(ctx context.Context, iface Interface) (*HopAction, error) {
	var ch int
	defaultChannels := []int{1, 6, 11}
	if iface.HopperIndex < len(defaultChannels) {
		ch = defaultChannels[iface.HopperIndex]
	} else if len(iface.Channels) > 0 {
		i := iface.HopperIndex % len(iface.Channels)
		ch = iface.Channels[i]
	} else {
		var ok bool
		ch, ok = netref.IndexToChannel[iface.HopperIndex]
		if !ok {
			return nil, fmt.Errorf("invalid hopper index %d", iface.HopperIndex)
		}
	}
	// log.Debug().Str("iface", iface.Name).
	// 	Stringer("hopper", h).
	// 	Msgf("hopping to channel %d", ch)
	if err := setChannel(ctx, iface.Name, ch); err != nil {
		return nil, err
	}
	action := &HopAction{
		Index:   iface.HopperIndex,
		Channel: ch,
	}
	return action, nil
}

type InvalidChannelError struct {
	Channel int
}

func (e InvalidChannelError) Error() string {
	return fmt.Sprintf("invalid channel %d", e.Channel)
}

func (h *StaticHopper) Update(
	iface Interface,
	action HopAction,
	obs HopObservation,
) {
	// do nothing
}

func NewUniformHopper() Hopper {
	return &UniformHopper{}
}

type UniformHopper struct{}

func (h UniformHopper) String() string {
	b, err := h.MarshalText()
	if err != nil {
		return fmt.Sprintf("invalid(%#v: %v)", h, err)
	}
	return string(b)
}

func (h UniformHopper) MarshalText() ([]byte, error) {
	return []byte("uniform"), nil
}

func (h UniformHopper) Hop(ctx context.Context, iface Interface) (*HopAction, error) {
	// Use available channels from interface, or fall back to common 2.4GHz channels
	channels := iface.Channels
	if len(channels) == 0 {
		// Default to common 2.4GHz channels if none specified
		channels = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
	}
	ch := channels[rand.Intn(len(channels))]
	if err := setChannel(ctx, iface.Name, ch); err != nil {
		return nil, err
	}
	action := &HopAction{
		Index:   netref.ChannelToIndex[ch],
		Channel: ch,
	}
	return action, nil
}

func (h *UniformHopper) Update(
	iface Interface,
	action HopAction,
	obs HopObservation,
) {
	// do nothing
}

func NewThompsonSamplingHopper() Hopper {
	return &ThompsonSamplingHopper{
		mu:         new(sync.Mutex),
		windowSize: 1000,
		decay:      1 - 1e-3,
		samplers:   make(map[string]*sample.ThompsonSampler),
	}
}

type ThompsonSamplingHopper struct {
	mu         *sync.Mutex
	windowSize int
	decay      float64
	samplers   map[string]*sample.ThompsonSampler
}

func (h ThompsonSamplingHopper) String() string {
	b, err := h.MarshalText()
	if err != nil {
		return fmt.Sprintf("invalid(%#v: %v)", h, err)
	}
	return string(b)
}

func (h ThompsonSamplingHopper) MarshalText() ([]byte, error) {
	return []byte("thompson_sampling"), nil
}

func (h ThompsonSamplingHopper) Hop(
	ctx context.Context,
	iface Interface,
) (*HopAction, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	desc, err := iface.Describe()
	if err != nil {
		return nil, fmt.Errorf("failed to describe iface: %w", err)
	}
	sampler, ok := h.samplers[iface.Name]
	if !ok {
		sampler = sample.NewThompsonSampler(len(desc.ChannelChoices), h.windowSize, h.decay)
		h.samplers[iface.Name] = sampler
	}

	index := sampler.Sample()
	ch := desc.ChannelChoices[index]
	if err := setChannel(ctx, iface.Name, ch); err != nil {
		return nil, err
	}
	action := &HopAction{
		Index:   index,
		Channel: ch,
	}
	return action, nil
}

func (h *ThompsonSamplingHopper) Update(
	iface Interface,
	action HopAction,
	obs HopObservation,
) {
	// A simple reward definition is to count up all the rewards from adjacent
	// channels.
	reward := 0
	for _, count := range obs.ChannelPackets {
		reward += count
	}
	sampler, ok := h.samplers[iface.Name]
	if !ok {
		panic(fmt.Sprintf("no sampler for iface %s", iface.Name))
	}
	sampler.Observe(action.Index, float64(reward))
}

// ValidateChannel checks if a channel number is valid
func ValidateChannel(channel int) bool {
	// Valid WiFi channels: 1-14 for 2.4GHz, 36-165 for 5GHz, 1-233 for 6GHz
	// This is a basic check - actual validation depends on band and regulatory domain
	return channel > 0 && channel <= 233
}

// ValidateInterfaceName checks if an interface name is safe to use
func ValidateInterfaceName(iface string) bool {
	if len(iface) == 0 || len(iface) > 16 {
		return false
	}
	// Interface names should be alphanumeric with some special chars
	for _, r := range iface {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

var platformWiFi PlatformWiFi

func init() {
	platformWiFi = NewPlatformWiFi()
}

func setChannel(
	ctx context.Context,
	iface string,
	channel int,
) error {
	if !ValidateInterfaceName(iface) {
		return fmt.Errorf("invalid interface name: %q", iface)
	}
	if !ValidateChannel(channel) {
		return InvalidChannelError{channel}
	}
	return platformWiFi.SetChannel(ctx, iface, channel)
}
