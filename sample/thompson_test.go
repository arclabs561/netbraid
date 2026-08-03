package sample_test

import (
	"math"
	"testing"

	"github.com/arclabs561/netwatch/sample"
	"gonum.org/v1/gonum/mat"
)

// TestUpdateNormalInverseWishart tests the UpdateNormalInverseWishart function
func TestUpdateNormalInverseWishart(t *testing.T) {
	// Define initial parameters
	mu := mat.NewVecDense(1, []float64{1})
	kappa := 1.0
	nu := 2.0
	sigma := mat.NewDense(1, 1, []float64{1})
	niw := &sample.NormalInverseWishart{Mu: mu, Kappa: kappa, Nu: nu, Sigma: sigma}

	// Define data
	data := mat.NewVecDense(5, []float64{1, 2, 3, 4, 5})

	// Call function
	newNiw, err := sample.UpdateNormalInverseWishart(niw, data)

	// Check for errors
	if err != nil {
		t.Errorf("UpdateNormalInverseWishart returned error: %v", err)
	}

	// Check resulting parameters
	if !floatEquals(newNiw.Kappa, 6.0, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Kappa: got %v want %v", newNiw.Kappa, 6.0)
	}

	if !floatEquals(newNiw.Nu, 7.0, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Nu: got %v want %v", newNiw.Nu, 7.0)
	}

	if !floatEquals(newNiw.Mu.At(0, 0), 8.0/3, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Mu: got %v want %v", newNiw.Mu.At(0, 0), 8.0/3)
	}

	expectedSigma := mat.NewDense(1, 1, []float64{43.0 / 3})
	if !matrixEquals(newNiw.Sigma, expectedSigma, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Sigma: got %v want %v", newNiw.Sigma, expectedSigma)
	}
}

func TestUpdateNormalInverseWishartNegative(t *testing.T) {
	// Define initial parameters
	mu := mat.NewVecDense(1, []float64{0})
	kappa := 1.0
	nu := 4.0
	sigma := mat.NewDense(1, 1, []float64{1})
	niw := &sample.NormalInverseWishart{Mu: mu, Kappa: kappa, Nu: nu, Sigma: sigma}

	// Define data
	data := mat.NewVecDense(5, []float64{-1, -2, -3, -4, -5})

	// Call function
	newNiw, err := sample.UpdateNormalInverseWishart(niw, data)

	// Check for errors
	if err != nil {
		t.Errorf("UpdateNormalInverseWishart returned error: %v", err)
	}

	// Check resulting parameters
	// Using 1e-9 as a threshold
	if !floatEquals(newNiw.Kappa, 6.0, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Kappa: got %v want %v", newNiw.Kappa, 6.0)
	}

	if !floatEquals(newNiw.Nu, 9.0, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Nu: got %v want %v", newNiw.Nu, 9.0)
	}

	if !floatEquals(newNiw.Mu.At(0, 0), -2.5, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Mu: got %v want %v", newNiw.Mu.At(0, 0), -2.5)
	}

	expectedSigma := mat.NewDense(1, 1, []float64{37.0 / 2.0})
	if !matrixEquals(newNiw.Sigma, expectedSigma, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Sigma: got %v want %v", newNiw.Sigma, expectedSigma)
	}
}

func TestUpdateNormalInverseWishartSingleDataPoint(t *testing.T) {
	// Define initial parameters
	mu := mat.NewVecDense(1, []float64{0})
	kappa := 1.0
	nu := 4.0
	sigma := mat.NewDense(1, 1, []float64{1})
	niw := &sample.NormalInverseWishart{Mu: mu, Kappa: kappa, Nu: nu, Sigma: sigma}

	// Define data
	data := mat.NewVecDense(1, []float64{1})

	// Call function
	newNiw, err := sample.UpdateNormalInverseWishart(niw, data)

	// Check for errors
	if err != nil {
		t.Errorf("UpdateNormalInverseWishart returned error: %v", err)
	}

	// Check resulting parameters
	// Using 1e-9 as a threshold
	if !floatEquals(newNiw.Kappa, 2.0, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Kappa: got %v want %v", newNiw.Kappa, 2.0)
	}

	if !floatEquals(newNiw.Nu, 5.0, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Nu: got %v want %v", newNiw.Nu, 5.0)
	}

	if !floatEquals(newNiw.Mu.At(0, 0), 0.5, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Mu: got %v want %v", newNiw.Mu.At(0, 0), 0.5)
	}

	expectedSigma := mat.NewDense(1, 1, []float64{3.0 / 2.0})
	if !matrixEquals(newNiw.Sigma, expectedSigma, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Sigma: got %v want %v", newNiw.Sigma, expectedSigma)
	}
}

func TestUpdateNormalInverseWishartLargeDataPoints(t *testing.T) {
	// Define initial parameters
	mu := mat.NewVecDense(1, []float64{1})
	kappa := 1.0
	nu := 4.0
	sigma := mat.NewDense(1, 1, []float64{1})
	niw := &sample.NormalInverseWishart{Mu: mu, Kappa: kappa, Nu: nu, Sigma: sigma}

	// Define data
	data := mat.NewVecDense(5, []float64{10000, 20000, 30000, 40000, 50000})

	// Call function
	newNiw, err := sample.UpdateNormalInverseWishart(niw, data)

	// Check for errors
	if err != nil {
		t.Errorf("UpdateNormalInverseWishart returned error: %v", err)
	}

	// Check resulting parameters
	// Using 1e-9 as a threshold
	if !floatEquals(newNiw.Kappa, 6.0, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Kappa: got %v want %v", newNiw.Kappa, 6.0)
	}

	if !floatEquals(newNiw.Nu, 9.0, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Nu: got %v want %v", newNiw.Nu, 9.0)
	}

	if !floatEquals(newNiw.Mu.At(0, 0), 150001.0/6.0, 1e-9) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Mu: got %v want %v", newNiw.Mu.At(0, 0), 150001.0/6.0)
	}

	expectedSigma := mat.NewDense(1, 1, []float64{10499700011.0 / 6.0})
	// This tolerance is tight enough to detect dropping the unit prior scale.
	if !matrixEquals(newNiw.Sigma, expectedSigma, 1e-12) {
		t.Errorf("UpdateNormalInverseWishart returned incorrect Sigma: got %v want %v", newNiw.Sigma, expectedSigma)
	}
}

func matrixEquals(A, B *mat.Dense, tol float64) bool {
	r1, c1 := A.Dims()
	r2, c2 := B.Dims()

	if r1 != r2 || c1 != c2 {
		return false
	}

	for i := 0; i < r1; i++ {
		for j := 0; j < c1; j++ {
			if !floatEquals(A.At(i, j), B.At(i, j), tol) {
				return false
			}
		}
	}

	return true
}

func floatEquals(a, b, tol float64) bool {
	scale := math.Max(1, math.Max(math.Abs(a), math.Abs(b)))
	return math.Abs(a-b) <= tol*scale
}
