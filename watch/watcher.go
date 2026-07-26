package watch

import (
	"context"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog/log"
)

// Watcher watches network activity and sends resultant Events to all of it's
// Subscribers.
type Watcher struct {
	events chan Event
	subs   []Subscriber
}

// NewWatcher creates a new watcher initialized with the given subscribers.
func NewWatcher(subs ...Subscriber) *Watcher {
	if len(subs) == 0 {
		subs = []Subscriber{NewSubLogger()}
	}
	return &Watcher{
		events: make(chan Event, 32),
		subs:   subs,
	}
}

// Watch scans the given src for packets, and publish resultant Events to all
// of it's registered Subscribers.
func (w *Watcher) Watch(ctx context.Context, src *gopacket.PacketSource) error {
	hosts := make(map[MAC]*Host)
	go w.ScanPackets(hosts, src.Packets())
	return w.Publish()
}

// WatchLive watches from the first good interface, and blocks forever.
func (w *Watcher) WatchLive(ctx context.Context, iface string) error {
	h, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	src := gopacket.NewPacketSource(h, h.LinkType())
	return w.Watch(ctx, src)

}

// WatchPCAP watches from a predefined pcap file.
func (w *Watcher) WatchPCAP(ctx context.Context, pcapPath string) error {
	h, err := pcap.OpenOffline(pcapPath)
	if err != nil {
		return err
	}
	src := gopacket.NewPacketSource(h, h.LinkType())
	return w.Watch(ctx, src)
}

// Publish endlessly reads incomming events, and sends a shallow copy of that
// event to each of this Watcher's Subscribers.
func (w *Watcher) Publish() error {
	for e := range w.events {
		for _, sub := range w.subs {
			if err := sub(e); err != nil {
				log.Err(err).Msg("failed to respond to event")
			}
		}
	}
	return nil
}

// NewSubConfig returns a new Subscriber
func NewSubConfig(
	path string,
	only []string,
) (Subscriber, error) {
	var conf Config
	if _, err := toml.DecodeFile(path, &conf); err != nil {
		return nil, err
	}
	// TODO: validate config, e.g. not on event and on events, etc.

	triggers := make(map[string]FilteredSubscriber)
	onlySet := stringSet(only)
	for name, spec := range conf.Triggers {
		if len(onlySet) > 0 && !onlySet[name] {
			continue
		}
		if spec.Disabled && !onlySet[name] {
			continue
		}
		log.Debug().Msgf("loading subscriber %s", name)
		trig, err := newTriggerFromConfig(spec)
		if err != nil {
			return nil, fmt.Errorf("trigger %q: %w", name, err)
		}
		triggers[name] = trig
	}
	if len(triggers) == 0 {
		log.Fatal().Msg("no subscribers loaded")
	}

	return func(e Event) error {
		for name, trig := range triggers {
			if !trig.ShouldDo(e) {
				continue
			}
			if err := trig.Sub(e); err != nil {
				log.Err(err).Msgf("failed to execute sub: %s", name)
			}
		}
		return nil
	}, nil
}

func newTriggerFromConfig(spec TriggerSpec) (FilteredSubscriber, error) {
	if spec.DoShell != "" || spec.OnShell != "" {
		return FilteredSubscriber{}, fmt.Errorf(
			"shell triggers are disabled; use a built-in trigger",
		)
	}
	if spec.DoBuiltin == "" {
		return FilteredSubscriber{}, fmt.Errorf("doBuiltin is required")
	}
	sub, err := newSubFromBuiltin(spec.DoBuiltin)
	if err != nil {
		return FilteredSubscriber{}, err
	}
	return FilteredSubscriber{
		Sub: sub,
		ShouldDo: func(e Event) bool {
			if spec.OnAny {
				return true
			}
			if len(spec.OnEventsExcept) > 0 {
				for _, ty := range spec.OnEventsExcept {
					if ty == e.Type {
						return false
					}
				}
				return true
			}
			for _, ty := range spec.OnEvents {
				if ty == e.Type {
					return true
				}
			}
			return false
		},
	}, nil
}

func newSubFromBuiltin(builtin string) (Subscriber, error) {
	switch strings.ToLower(builtin) {
	case "null":
		return NewSubNull(), nil
	case "log":
		return NewSubLogger(), nil
	default:
		return nil, fmt.Errorf("unsupported built-in trigger %q", builtin)
	}
}

func stringSet(slice []string) map[string]bool {
	m := make(map[string]bool)
	for _, s := range slice {
		m[s] = true
	}
	return m
}
