package sample

import (
	"errors"
	"fmt"
	"math"

	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/gonum/stat/distuv"
)

type Dist interface {
	Sample() float64
}

type Gamma struct {
	Alpha float64
	Beta  float64
}

func (g Gamma) String() string {
	return fmt.Sprintf("Gamma(alpha=%0.3f, beta=%0.3f)", g.Alpha, g.Beta)
}

func (g Gamma) Sample() float64 {
	return distuv.Gamma{
		Alpha: g.Alpha,
		Beta:  g.Beta,
	}.Rand()
}

type ThompsonSampler struct {
	arms       int
	window     int
	priors     []Dist
	alphaPrior float64
	betaPrior  float64
	discounts  []float64
	rewards    [][]float64
}

func NewThompsonSampler(
	arms int, // e.g. 14
	window int, // e.g. 1000
	discount float64, // e.g. 1-1e-3
) *ThompsonSampler {
	curr := 1.0
	discounts := make([]float64, window)
	for i := 0; i < window; i++ {
		discounts[i] = curr
		curr *= discount
	}
	alphaPrior, betaPrior := 1e-3, 1e-3 // jeffrey's prior
	priors := make([]Dist, arms)
	for i := 0; i < arms; i++ {
		priors[i] = Gamma{Alpha: alphaPrior, Beta: betaPrior}
	}
	return &ThompsonSampler{
		arms:       arms,
		window:     window,
		priors:     priors,
		alphaPrior: alphaPrior,
		betaPrior:  betaPrior,
		discounts:  discounts,
		rewards:    make([][]float64, arms),
	}
}

func (ts ThompsonSampler) Sample() int {
	if len(ts.priors) == 0 {
		panic("no arms to sample")
	}
	best := math.Inf(-1)
	bestIndex := -1
	for i, prior := range ts.priors {
		if x := prior.Sample(); x > best {
			best = x
			bestIndex = i
		}
	}
	return bestIndex
}

func (ts ThompsonSampler) Params(arm int) []float64 {
	g := ts.priors[arm].(Gamma)
	return []float64{g.Alpha, g.Beta}
}

func (ts ThompsonSampler) Observe(arm int, reward float64) {
	ts.rewards[arm] = append(ts.rewards[arm], reward)
	if len(ts.rewards[arm]) > ts.window {
		ts.rewards[arm] = ts.rewards[arm][1:]
	}
	alpha := dot(ts.rewards[arm], ts.discounts) + ts.alphaPrior
	beta := ts.betaPrior
	for i := range ts.rewards[arm] {
		beta += ts.discounts[i]
	}
	posterior := Gamma{Alpha: alpha, Beta: beta}
	ts.priors[arm] = posterior
}

func dot(xs, ys []float64) float64 {
	t := 0.0
	for i, x := range xs {
		t += x * ys[i]
	}
	return t
}

type NormalInverseWishart struct {
	Mu    *mat.VecDense
	Kappa float64
	Nu    float64
	Sigma *mat.Dense
}

// UpdateNormalInverseWishart updates the parameters of a Normal-inverse-Wishart distribution based on observed data.
func UpdateNormalInverseWishart(niw *NormalInverseWishart, data *mat.VecDense) (*NormalInverseWishart, error) {
	if data.Len() == 0 {
		return nil, errors.New("data length must be greater than 0")
	}

	// Initialize and compute necessary values
	n := float64(data.Len())
	meanData := mat.Sum(data) / n
	newNiw := &NormalInverseWishart{
		Mu:    mat.NewVecDense(1, nil),
		Kappa: niw.Kappa + n,
		Nu:    niw.Nu + n,
		Sigma: mat.NewDense(1, 1, nil),
	}

	// Update mean
	newNiw.Mu.ScaleVec(niw.Kappa/(niw.Kappa+n), niw.Mu)
	newNiw.Mu.AddScaledVec(newNiw.Mu, n/(niw.Kappa+n), mat.NewVecDense(1, []float64{meanData}))

	// Compute sum of squares matrix
	ss := computeSumOfSquares(data, meanData)

	// Compute covariance update
	diff := mat.NewVecDense(1, []float64{niw.Mu.AtVec(0) - meanData})
	outer := mat.NewDense(1, 1, nil)
	outer.Mul(diff, diff.T())
	outer.Scale(niw.Kappa*n/newNiw.Kappa, outer)

	// Update covariance
	newNiw.Sigma.Add(niw.Sigma, outer)
	newNiw.Sigma.Add(newNiw.Sigma, ss)

	// Print intermediate calculations for debugging
	fmt.Printf("Mu: %v\n", newNiw.Mu)
	fmt.Printf("Sigma: %v\n", newNiw.Sigma)

	return newNiw, nil
}

// computeSumOfSquares computes the sum of squares of the deviations from the mean for the given data
func computeSumOfSquares(data *mat.VecDense, mean float64) *mat.Dense {
	dataLen := data.Len()

	// Create a zero matrix to hold the sum of squares
	ss := mat.NewDense(1, 1, nil)

	for i := 0; i < dataLen; i++ {
		// Compute deviation from the mean for each data point
		deviation := data.AtVec(i) - mean

		// Add the square of the deviation to the sum of squares
		ss.Add(ss, mat.NewDense(1, 1, []float64{deviation * deviation}))
	}

	return ss
}
