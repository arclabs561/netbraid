package swucb

import (
	"errors"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestNewSWUCBAlgorithm(t *testing.T) {
	algo := NewSWUCBAlgorithm(5, 100, time.Second)
	if algo == nil {
		t.Fatalf("NewSWUCBAlgorithm should not return nil")
	}
	if algo.numChannels != 5 {
		t.Errorf("Expected numChannels to be 5, got %d", algo.numChannels)
	}
	if algo.w != 100 {
		t.Errorf("Expected sliding window size to be 100, got %d", algo.w)
	}
	if algo.TDefault != time.Second {
		t.Errorf("Expected TDefault to be 1s, got %v", algo.TDefault)
	}
}

func TestSWUCBAlgorithm_Run(t *testing.T) {
	observer := func(channel int, duration time.Duration) (int, error) {
		if channel < 0 {
			return 0, errors.New("invalid channel")
		}
		return 0, nil
	}

	algo := NewSWUCBAlgorithm(5, 100, time.Second)
	err := algo.Run(observer, &OptRunMaxSteps{1000})
	if err != nil {
		t.Errorf("Expected Run to return no error, got %v", err)
	}
}

func TestSWUCBAlgorithm_Probabilistic(t *testing.T) {
	packetRates := []float64{100, 300, 500, 700, 1000} // packets per second
	packetObserver := func(channel int, duration time.Duration) (int, error) {
		packetRate := packetRates[channel]
		return int(packetRate * duration.Seconds()), nil
	}

	algo := NewSWUCBAlgorithm(len(packetRates), 100, 10*time.Millisecond)
	err := algo.Run(packetObserver, &OptRunMaxSteps{10000})
	if err != nil {
		t.Fatalf("Expected Run to return no error, got %v", err)
	}

	if got, want := mostObservedChannel(algo.n), len(packetRates)-1; got != want {
		t.Errorf("most observed channel = %d, want highest-rate channel %d; counts=%v", got, want, algo.n)
	}
}

func TestSWUCBAlgorithm_WarmupObservesEveryChannelOnce(t *testing.T) {
	const channels = 4
	var durations []time.Duration
	observer := func(_ int, duration time.Duration) (int, error) {
		durations = append(durations, duration)
		return 1, nil
	}

	algo := NewSWUCBAlgorithm(channels, 5, 250*time.Millisecond)
	if err := algo.Run(observer, &OptRunMaxSteps{channels}); err != nil {
		t.Fatalf("Run returned an error: %v", err)
	}

	if want := []int{1, 1, 1, 1}; !reflect.DeepEqual(algo.n, want) {
		t.Fatalf("warmup observation counts = %v, want %v", algo.n, want)
	}
	for _, duration := range durations {
		if duration != algo.TDefault {
			t.Fatalf("warmup duration = %v, want %v; durations=%v", duration, algo.TDefault, durations)
		}
	}
}

func TestSWUCBAlgorithm_UsesDurationUnitsAfterWindowFills(t *testing.T) {
	var durations []time.Duration
	observer := func(_ int, duration time.Duration) (int, error) {
		durations = append(durations, duration)
		if duration <= 0 {
			return 0, errors.New("observation duration must be positive")
		}
		return int(10 * duration.Seconds()), nil
	}

	algo := NewSWUCBAlgorithm(1, 1, time.Second)
	if err := algo.Run(observer, &OptRunMaxSteps{3}); err != nil {
		t.Fatalf("Run returned an invalid observation duration: %v", err)
	}

	want := []time.Duration{time.Second, 100 * time.Millisecond, 100 * time.Millisecond}
	if !reflect.DeepEqual(durations, want) {
		t.Fatalf("observation durations = %v, want %v", durations, want)
	}
}

func TestSWUCBAlgorithm_VaryingTDefault(t *testing.T) {
	packetRates := []float64{100, 200, 300, 400, 500}
	TDefaults := []time.Duration{100 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second}

	for _, TDefault := range TDefaults {
		algo := NewSWUCBAlgorithm(len(packetRates), 5, TDefault)
		err := algo.Run(PacketObserverForRates(packetRates), &OptRunMaxSteps{1000})
		if err != nil {
			t.Errorf("Error running algorithm with TDefault = %v: %v", TDefault, err)
		}

		if got, want := mostObservedChannel(algo.ObservationCounts()), len(packetRates)-1; got != want {
			t.Errorf("most observed channel with TDefault %v = %d, want %d; counts=%v", TDefault, got, want, algo.n)
		}
	}
}

func TestSWUCBAlgorithm_VaryingWindowSizes(t *testing.T) {
	packetRates := []float64{100, 200, 300, 400, 500}
	windowSizes := []int{5, 10, 20}

	for _, w := range windowSizes {
		algo := NewSWUCBAlgorithm(len(packetRates), w, 10*time.Millisecond)
		err := algo.Run(PacketObserverForRates(packetRates), &OptRunMaxSteps{1000})
		if err != nil {
			t.Errorf("Error running algorithm with window size = %d: %v", w, err)
		}

		if got, want := mostObservedChannel(algo.ObservationCounts()), len(packetRates)-1; got != want {
			t.Errorf("most observed channel with window size %d = %d, want %d; counts=%v", w, got, want, algo.n)
		}
	}
}

func TestSWUCBAlgorithm_VaryingPacketRates(t *testing.T) {
	packetRateScenarios := [][]float64{
		{100, 200, 300, 400, 500},
		{500, 400, 300, 200, 100},
	}

	for _, packetRates := range packetRateScenarios {
		algo := NewSWUCBAlgorithm(len(packetRates), 5, 10*time.Millisecond)
		err := algo.Run(PacketObserverForRates(packetRates), &OptRunMaxSteps{1000})
		if err != nil {
			t.Errorf("Error running algorithm with packet rates = %v: %v", packetRates, err)
		}

		observationCounts := algo.ObservationCounts()
		want := 0
		if packetRates[len(packetRates)-1] > packetRates[0] {
			want = len(packetRates) - 1
		}
		if got := mostObservedChannel(observationCounts); got != want {
			t.Errorf("most observed channel for rates %v = %d, want %d; counts=%v", packetRates, got, want, observationCounts)
		}
	}
}

func TestSWUCBAlgorithm_RejectsInvalidConfigurationAndObservations(t *testing.T) {
	observerCalled := false
	observer := func(_ int, _ time.Duration) (int, error) {
		observerCalled = true
		return 0, nil
	}
	invalid := []*SWUCBAlgorithm{
		NewSWUCBAlgorithm(0, 1, time.Second),
		NewSWUCBAlgorithm(1, 0, time.Second),
		NewSWUCBAlgorithm(1, 1, 0),
	}
	for _, algo := range invalid {
		if err := algo.Run(observer, &OptRunMaxSteps{1}); err == nil {
			t.Errorf("Run accepted invalid configuration: %+v", algo)
		}
	}
	if observerCalled {
		t.Fatal("invalid configuration reached the packet observer")
	}

	algo := NewSWUCBAlgorithm(1, 1, time.Second)
	if err := algo.Run(observer, &OptRunMaxSteps{-1}); err == nil {
		t.Error("Run accepted a negative maximum step count")
	}
	if observerCalled {
		t.Fatal("invalid maximum step count reached the packet observer")
	}

	negativeObserver := func(_ int, _ time.Duration) (int, error) { return -1, nil }
	if err := algo.Run(negativeObserver, &OptRunMaxSteps{1}); err == nil {
		t.Error("Run accepted a negative packet count")
	}
}

func PacketObserverForRates(packetRates []float64) PacketObserver {
	return func(channel int, duration time.Duration) (int, error) {
		if channel < 0 || channel >= len(packetRates) {
			return 0, errors.New("invalid channel")
		}
		packetRate := packetRates[channel]
		return int(math.Round(packetRate * duration.Seconds())), nil
	}
}

func mostObservedChannel(counts []int) int {
	mostObserved := 0
	for channel := 1; channel < len(counts); channel++ {
		if counts[channel] > counts[mostObserved] {
			mostObserved = channel
		}
	}
	return mostObserved
}
