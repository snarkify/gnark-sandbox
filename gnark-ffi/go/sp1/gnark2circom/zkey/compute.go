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
	domainSize := domain.Cardinality
	pointsH := make([]bn254.G1Affine, domainSize)
	
	// Get the G1 generator point
	g1Gen, _, _, _ := bn254.Generators()
	
	// For each H element in the domain, convert to a G1 point using scalar multiplication
	for i := uint64(0); i < domainSize; i++ {
		// If we have fewer H elements than the domain size, pad with zeros
		if i < uint64(len(h)) {
			// Convert the field element to scalar for G1 point multiplication
			var scalar big.Int
			h[i].BigInt(&scalar)
			
			// Compute g1Gen * hElement (scalar multiplication)
			var p bn254.G1Jac
			p.ScalarMultiplication(&g1Gen, &scalar)
			
			// Convert to affine coordinates and store in result
			pointsH[i].FromJacobian(&p)
		} else {
			// For any indices beyond the provided H elements, use the point at infinity
			pointsH[i].X.SetZero()
			pointsH[i].Y.SetZero()
		}
	}
	
	return pointsH, nil
}
