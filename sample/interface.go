package sample

type Sampler interface {
	// Number of arms
	Len() int
	// Sample arm to play
	Sample() int
	// Observe reward for selected arm.
	Observe(arm int, reward float64)
	// Return implementation specific slice of parameters for the given
	// arm. May be nil.
	Params(arm int) []float64
}
