package zkey

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

// ReconstructPointsH builds the fixed G1 basis (PointsH) from the FFT domain using the H elements
// This function converts Gnark's H elements ([]fr.Element) to SnarkJS's PointsH ([]bn254.G1Affine)
func ReconstructPointsH(domain fft.Domain, h []fr.Element) ([]bn254.G1Affine, error) {
	// Allocate the result array with domain size
	pointsH := make([]bn254.G1Affine, domain.Cardinality)

	// Get the generator point for G1
	g1GenAffine := bn254.G1Affine{}
	g1GenJac, _, _, _ := bn254.Generators()
	g1GenAffine.FromJacobian(&g1GenJac)

	// For each H element, convert to a G1 point using scalar multiplication
	for i, hElement := range h {
		if i >= len(pointsH) {
			break
		}

		// Convert field element to standard (non-Montgomery) representation
		bigInt := new(big.Int)
		hElement.BigInt(bigInt) // This handles Montgomery conversion correctly

		// Compute g1Gen * hElement (scalar multiplication)
		pointsH[i].ScalarMultiplication(&g1GenAffine, bigInt)
	}

	return pointsH, nil
}
