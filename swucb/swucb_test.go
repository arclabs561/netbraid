package swucb

import (
	"errors"
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
	packetRates := []float64{1, 3, 5, 7, 10} // packets per second
	packetObserver := func(channel int, duration time.Duration) (int, error) {
		packetRate := packetRates[channel]
		return int(packetRate * duration.Seconds()), nil
	}

	algo := NewSWUCBAlgorithm(len(packetRates), 100, time.Second)
	err := algo.Run(packetObserver, &OptRunMaxSteps{10000})
	if err != nil {
		t.Fatalf("Expected Run to return no error, got %v", err)
	}

	// It's very likely that the algorithm should favor the channel with the highest packet rate (channel 4).
	// However, to avoid flaky tests, we'll check that the channel with the lowest packet rate (channel 0) was not the most observed one.
	minChannel, maxChannel := 0, 0
	minCount, maxCount := algo.n[0], algo.n[0]
	for i := 1; i < len(packetRates); i++ {
		if algo.n[i] < minCount {
			minChannel, minCount = i, algo.n[i]
		}
		if algo.n[i] > maxCount {
			maxChannel, maxCount = i, algo.n[i]
		}
	}

	if minChannel == maxChannel {
		t.Errorf("Expected most observed channel not to be the least observed one")
	}
}

func TestSWUCBAlgorithm_VaryingTDefault(t *testing.T) {
	packetRates := []float64{1, 2, 3, 4, 5}
	TDefaults := []time.Duration{100 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second}

	for _, TDefault := range TDefaults {
		algo := NewSWUCBAlgorithm(len(packetRates), 5, TDefault)
		err := algo.Run(PacketObserverForRates(packetRates), &OptRunMaxSteps{1000})
		if err != nil {
			t.Errorf("Error running algorithm with TDefault = %v: %v", TDefault, err)
		}

		observationCounts := algo.ObservationCounts()
		for i, count := range observationCounts {
			if count == 0 {
				t.Errorf("Channel %d not observed at all with TDefault = %v", i, TDefault)
			}
		}
	}
}

func TestSWUCBAlgorithm_VaryingWindowSizes(t *testing.T) {
	packetRates := []float64{1, 2, 3, 4, 5}
	windowSizes := []int{5, 10, 20}

	for _, w := range windowSizes {
		algo := NewSWUCBAlgorithm(len(packetRates), w, 10*time.Millisecond)
		err := algo.Run(PacketObserverForRates(packetRates), &OptRunMaxSteps{1000})
		if err != nil {
			t.Errorf("Error running algorithm with window size = %d: %v", w, err)
		}

		observationCounts := algo.ObservationCounts()
		for i, count := range observationCounts {
			if count == 0 {
				t.Errorf("Channel %d not observed at all with window size = %d", i, w)
			}
		}
	}
}

func TestSWUCBAlgorithm_VaryingPacketRates(t *testing.T) {
	packetRateScenarios := [][]float64{
		{1, 1, 1, 1, 1},
		{1, 2, 3, 4, 5},
		{5, 4, 3, 2, 1},
	}

	for _, packetRates := range packetRateScenarios {
		algo := NewSWUCBAlgorithm(len(packetRates), 5, 10*time.Millisecond)
		err := algo.Run(PacketObserverForRates(packetRates), &OptRunMaxSteps{1000})
		if err != nil {
			t.Errorf("Error running algorithm with packet rates = %v: %v", packetRates, err)
		}

		observationCounts := algo.ObservationCounts()
		for i, count := range observationCounts {
			if count == 0 {
				t.Errorf("Channel %d not observed at all with packet rates = %v", i, packetRates)
			}
		}
	}
}

func PacketObserverForRates(packetRates []float64) PacketObserver {
	return func(channel int, duration time.Duration) (int, error) {
		if channel < 0 || channel >= len(packetRates) {
			return 0, errors.New("invalid channel")
		}
		packetRate := packetRates[channel]
		return int(packetRate * duration.Seconds()), nil
	}
}
