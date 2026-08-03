package swucb

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/samber/mo"
)

// PacketObserver is a function type that represents the packet observation process for a given channel and duration.
// The function should return an error if the packet observation process encounters any issues.
type PacketObserver func(channel int, duration time.Duration) (int, error)

// SWUCBAlgorithm represents the Sliding-Window Upper Confidence Bound algorithm for channel selection.
type SWUCBAlgorithm struct {
	numChannels int           // The total number of channels
	w           int           // The sliding window size for tracking recent packet arrival rates
	TDefault    time.Duration // The default time duration to observe a channel when its sliding window is not full
	n           []int         // The number of times each channel has been observed

}

// NewSWUCBAlgorithm creates a new instance of the SWUCBAlgorithm with the given parameters.
func NewSWUCBAlgorithm(numChannels int, w int, TDefault time.Duration) *SWUCBAlgorithm {
	return &SWUCBAlgorithm{
		numChannels: numChannels,
		w:           w,
		TDefault:    TDefault,
		n:           nil,
	}
}

func (a *SWUCBAlgorithm) ObservationCounts() []int {
	return a.n
}

type packetObservation struct {
	packets  int
	duration time.Duration
}

func packetRate(observations []packetObservation) float64 {
	packets := 0
	duration := time.Duration(0)
	for _, observation := range observations {
		packets += observation.packets
		duration += observation.duration
	}
	if duration <= 0 {
		return 0
	}
	return float64(packets) / duration.Seconds()
}

type RunOption interface {
	runOption()
}

type OptRunMaxSteps struct {
	MaxSteps int
}

func (o *OptRunMaxSteps) runOption() {}

// Run executes the SW-UCB algorithm for the given number of time steps.
func (a *SWUCBAlgorithm) Run(
	packetObserver PacketObserver,
	opts ...RunOption,
) error {
	if a.numChannels < 1 {
		return errors.New("number of channels must be at least 1")
	}
	if a.w < 1 {
		return errors.New("sliding window size must be at least 1")
	}
	if a.TDefault <= 0 {
		return errors.New("default observation duration must be positive")
	}
	n := make([]int, a.numChannels)
	L := make([][]packetObservation, a.numChannels)
	for channel := range L {
		L[channel] = make([]packetObservation, 0, a.w)
	}

	maxSteps := mo.None[int]()
	for _, opt := range opts {
		switch opt := opt.(type) {
		case *OptRunMaxSteps:
			if opt.MaxSteps < 0 {
				return errors.New("maximum steps must not be negative")
			}
			maxSteps = mo.Some(opt.MaxSteps)
		default:
			panic(fmt.Sprintf("unknown option type: %#v", opt))
		}
	}

	t := 1
	tick := func() bool {
		if maxSteps.IsAbsent() {
			return true
		}
		if t <= maxSteps.MustGet() {
			t++
			return true
		}
		return false
	}
	for tick() {
		maxUCB, selectedChannel := -1.0, -1
		unobserved := -1
		for i := 0; i < a.numChannels; i++ {
			ni := float64(n[i])
			if ni == 0 {
				unobserved = i
				continue
			}
			avgReward := packetRate(L[i])
			UCB := avgReward + math.Sqrt(2*math.Log(float64(t))/math.Min(float64(a.w), ni))
			if UCB > maxUCB {
				maxUCB, selectedChannel = UCB, i
			}
		}

		if unobserved != -1 {
			selectedChannel = unobserved
		}

		var T time.Duration
		windowRate := packetRate(L[selectedChannel])
		if n[selectedChannel] < a.w || windowRate <= 0 {
			T = a.TDefault
		} else {
			T = time.Duration(float64(time.Second) * float64(a.w) / windowRate)
			if T <= 0 {
				T = time.Nanosecond
			}
		}

		packetsObserved, err := packetObserver(selectedChannel, T)
		if err != nil {
			return err
		}
		if packetsObserved < 0 {
			return errors.New("observed packet count must not be negative")
		}

		n[selectedChannel]++
		L[selectedChannel] = append(L[selectedChannel], packetObservation{
			packets:  packetsObserved,
			duration: T,
		})
		if len(L[selectedChannel]) > a.w {
			L[selectedChannel] = L[selectedChannel][1:]
		}
	}

	a.n = n
	return nil
}
