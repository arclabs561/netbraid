package sample

// // Define the reward function
// func rewardFunction(channel float64) float64 {
// 	// Replace this function with your specific implementation
// 	return math.Sin(channel)
// }

// type gpModel struct {
// 	X            *mat.Dense
// 	y            mat.Vector
// 	alpha        float64
// 	kernelParams []float64
// }

// func (gp *gpModel) fit(X *mat.Dense, y mat.Vector) {
// 	gp.X = X
// 	gp.y = y
// }

// func (gp *gpModel) rbfKernel(X1, X2 mat.Matrix, lengthScale float64) *mat.Dense {
// 	rows1, cols1 := X1.Dims()
// 	rows2, _ := X2.Dims()

// 	kernel := mat.NewDense(rows1, rows2, nil)
// 	for i := 0; i < rows1; i++ {
// 		for j := 0; j < rows2; j++ {
// 			distanceSquared := 0.0
// 			for k := 0; k < cols1; k++ {
// 				distanceSquared += math.Pow(X1.At(i, k)-X2.At(j, k), 2)
// 			}
// 			kernel.Set(i, j, math.Exp(-distanceSquared/(2*lengthScale*lengthScale)))
// 		}
// 	}
// 	return kernel
// }

// func (gp *gpModel) predict(x mat.Vector) (float64, float64) {
// 	return 0, 0
// 	// rows, _ := gp.X.Dims()
// 	// K := gp.rbfKernel(gp.X, gp.X, gp.kernelParams[0])
// 	// Ky := mat.NewDense(rows, rows, nil)
// 	// Ky.CloneFrom(K)
// 	// Ky.Apply(func(i, j int, v float64) float64 {
// 	// 	return v + gp.alpha*math.Pow(gp.kernelParams[1], 2)
// 	// }, Ky)

// 	// // Compute the Cholesky decomposition of Ky
// 	// var chol mat.Cholesky
// 	// ok := chol.Factorize(Ky)
// 	// if !ok {
// 	// 	panic("Cholesky decomposition failed")
// 	// }

// 	// // Compute the inverse of Ky
// 	// var KyInv mat.Dense
// 	// err := KyInv.SolveCholesky(&chol, mat.NewDense(rows, rows, nil).Eye(rows, rows))
// 	// if err != nil {
// 	// 	panic("Matrix inversion failed")
// 	// }

// 	// Ks := gp.rbfKernel(gp.X, mat.DenseCopyOf(mat.NewDense(1, 1, []float64{x.AtVec(0)})), gp.kernelParams[0])

// 	// // Compute the mean
// 	// mu := mat.Dot(Ks.T(), &KyInv).(*mat.Dense)
// 	// mu.Mul(mu, gp.y)

// 	// // Compute the standard deviation
// 	// var Kss mat.Dense
// 	// Kss.CloneFrom(gp.rbfKernel(mat.DenseCopyOf(mat.NewDense(1, 1, []float64{x.AtVec(0)})), mat.DenseCopyOf(mat.NewDense(1, 1, []float64{x.AtVec(0)})), gp.kernelParams[0]))
// 	// Kss.Sub(&Kss, mat.Dot(Ks.T(), &KyInv).(*mat.Dense).Mul(mat.Dot(Ks.T(), &KyInv), Ks))

// 	// return mu.At(0, 0), math.Sqrt(Kss.At(0, 0))
// }

// func acquisitionFunction(gp *gpModel, channels []float64, yMax float64) float64 {
// 	maxEI := math.Inf(-1)
// 	bestChannel := -1.0

// 	for _, channel := range channels {
// 		x := mat.NewVecDense(1, []float64{channel})
// 		mu, sigma := gp.predict(x)

// 		EI := (mu-yMax)*distuv.UnitNormal.CDF((mu-yMax)/sigma) +
// 			sigma*distuv.UnitNormal.Prob((mu-yMax)/sigma)

// 		if EI > maxEI {
// 			maxEI = EI
// 			bestChannel = channel
// 		}
// 	}

// 	return bestChannel
// }

// func main() {
// 	channels := []float64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
// 	nInitialSamples := 5
// 	alpha := 1e-5

// 	// Collect initial samples
// 	XSample := mat.NewDense(nInitialSamples, 1, nil)
// 	ySample := mat.NewVecDense(nInitialSamples, nil)

// 	for i := 0; i < nInitialSamples; i++ {
// 		channel := channels[rand.Intn(len(channels))]
// 		XSample.Set(i, 0, channel)
// 		ySample.SetVec(i, rewardFunction(channel))
// 	}

// 	// Initialize the Gaussian Process
// 	gp := &gpModel{
// 		alpha:        alpha,
// 		kernelParams: []float64{1.0, 1.0}, // Replace with appropriate kernel parameters
// 	}

// 	// Update the Gaussian Process with initial samples
// 	gp.fit(XSample, ySample)

// 	// Gaussian Process optimization loop
// 	nIterations := 20
// 	singleRowMatrix := mat.NewDense(1, 1, nil)
// 	for i := 0; i < nIterations; i++ {
// 		// Use the acquisition function to find the next channel to sample
// 		nextChannel := acquisitionFunction(gp, channels, mat.Max(ySample))

// 		// Collect the reward for the chosen channel
// 		nextReward := rewardFunction(nextChannel)

// 		// Update the samples and fit the Gaussian Process

// 		XSampleTmp := mat.NewDense(XSample.RawMatrix().Rows+1, XSample.RawMatrix().Cols, nil)
// 		singleRowMatrix.Set(0, 0, nextChannel)
// 		XSampleTmp.Stack(XSample, singleRowMatrix)
// 		XSample = XSampleTmp

// 		ySampleTmp := mat.NewDense(ySample.Len()+1, 1, nil)
// 		singleRowMatrix.Set(0, 0, nextReward)
// 		ySampleTmp.Augment(mat.DenseCopyOf(ySample), singleRowMatrix)
// 		ySample = mat.VecDenseCopyOf(ySampleTmp.ColView(0))

// 		gp.fit(XSample, ySample)
// 	}

// 	// Find the channel with the highest reward
// 	bestChannel := channels[0]
// 	maxReward := ySample.AtVec(0)
// 	for i := 1; i < ySample.Len(); i++ {
// 		reward := ySample.AtVec(i)
// 		if reward > maxReward {
// 			maxReward = reward
// 			bestChannel = XSample.At(i, 0)
// 		}
// 	}

// 	fmt.Printf("Best channel: %.0f\n", bestChannel)
// }
