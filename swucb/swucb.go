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

// sum returns the sum of the elements in the given slice.
func sum(arr []int) float64 {
	total := 0
	for _, v := range arr {
		total += v
	}
	return float64(total)
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
	n, r, L := make([]int, a.numChannels), make([]float64, a.numChannels), make([][]int, a.numChannels)
	for channel := range L {
		L[channel] = make([]int, 0, a.w)
	}

	maxSteps := mo.None[int]()
	for _, opt := range opts {
		switch opt := opt.(type) {
		case *OptRunMaxSteps:
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
			avgReward := sum(L[i]) / math.Min(float64(a.w), ni)
			UCB := avgReward + math.Sqrt(2*math.Log(float64(t))/math.Min(float64(a.w), ni))
			if UCB > maxUCB {
				maxUCB, selectedChannel = UCB, i
			}
		}

		if unobserved != -1 {
			selectedChannel = unobserved
		}

		var T time.Duration
		if n[selectedChannel] < a.w {
			T = a.TDefault
		} else {
			T = time.Duration(float64(a.w) / sum(L[selectedChannel]))
		}

		packetsObserved, err := packetObserver(selectedChannel, T)
		if err != nil {
			return err
		}

		r[selectedChannel] += float64(packetsObserved)
		n[selectedChannel]++
		L[selectedChannel] = append(L[selectedChannel], packetsObserved)
		if len(L[selectedChannel]) > a.w {
			L[selectedChannel] = L[selectedChannel][1:]
		}
	}

	a.n = n
	return nil
}
