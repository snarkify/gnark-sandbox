package zkey

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

// ReconstructPointsH builds the fixed G1 basis (PointsH) from the polynomial h(x) in coefficient form
// h(x) represents (A(x)*B(x) - C(x))/Z(x) from the QAP representation of the circuit
// domainSize must match the length of h elements to maintain mathematical correctness
func ReconstructPointsH(domain fft.Domain, h []fr.Element, domainSize uint32) ([]bn254.G1Affine, error) {
	// Check if the domainSize matches h length for mathematical correctness
	if uint64(domainSize) != uint64(len(h)) {
		return nil, fmt.Errorf("error: domainSize (%d) must equal h length (%d) for correct polynomial representation", domainSize, len(h))
	}

	// Allocate the result array with specified domain size
	pointsH := make([]bn254.G1Affine, domainSize)

	// Get the generator point for G1
	g1GenAffine := bn254.G1Affine{}
	g1GenJac, _, _, _ := bn254.Generators()
	g1GenAffine.FromJacobian(&g1GenJac)

	// Map each coefficient of h to a G1 point - this creates the proper polynomial commitment
	// h should already be in coefficient form from the computeH function
	for i := uint64(0); i < uint64(domainSize); i++ {
		// Convert field element to standard representation
		bigInt := new(big.Int)
		h[i].BigInt(bigInt) // This handles Montgomery conversion correctly

		// Compute pointsH[i] = h[i] * G1
		pointsH[i].ScalarMultiplication(&g1GenAffine, bigInt)
	}

	return pointsH, nil
}
