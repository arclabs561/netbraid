package watch

import (
	"fmt"

	"github.com/rs/zerolog/log"
)

// Subscriber handles a single event and reacts to it. A Subscriber can be
// wrapped within a Trigger if they wish to filter which Events are received by
// the Subscriber.
type Subscriber func(e Event) error

// FilteredSubscriber combines a Subscriber with an event filter, so that only
// those events that return true for ShouldDo are given to enclosed Subscriber.
type FilteredSubscriber struct {
	Sub      Subscriber
	ShouldDo func(e Event) bool
}

// NewSubNull does nothing for each event. This is useful for debugging
// handling of events, where you don't necessarily want to do anything in
// response to the events.
func NewSubNull() Subscriber {
	return func(e Event) error {
		return nil
	}
}

// NewSubLogger returns a new logging Subscriber. For each event, some
// hopefully useful information is logged.
func NewSubLogger() Subscriber {
	return func(e Event) error {
		switch e.Type {
		case HostTouch:
			e := e.Body.(EventHostTouch)
			log.Info().Msgf("touch %s", e.Host)
		case HostNew:
			e := e.Body.(EventHostNew)
			log.Info().Msgf("new %s", e.Host)
		case HostLost:
			e := e.Body.(EventHostLost)
			log.Info().Msgf("drop %s (up %s)", e.Host, e.Up)
		case HostFound:
			e := e.Body.(EventHostFound)
			log.Info().Msgf("return %s (down %s)", e.Host, e.Down)
		case HostARPScanStart:
			e := e.Body.(EventHostARPScanStart)
			log.Info().Msgf("host started arp scan %s", e.Host)
		case HostARPScanStop:
			e := e.Body.(EventHostARPScanStop)
			log.Info().Msgf("host stopped arp scan %s (up %s)", e.Host, e.Up)
		case PortTouch:
			e := e.Body.(EventPortTouch)
			log.Info().Msgf("touch %s on %s", e.Port, e.Host)
		case PortNew:
			e := e.Body.(EventPortNew)
			log.Info().Msgf("new %s on %s", e.Port, e.Host)
		case PortLost:
			e := e.Body.(EventPortLost)
			log.Info().Msgf("drop %s (up %s) on %s", e.Port, e.Up, e.Host)
		case PortFound:
			e := e.Body.(EventPortFound)
			log.Info().Msgf("return %s (down %s) on %s", e.Port, e.Down, e.Host)
		default:
			panic(fmt.Sprintf("unhandled event type: %#v", e))
		}
		return nil
	}
}
