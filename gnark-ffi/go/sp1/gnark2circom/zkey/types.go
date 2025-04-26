package zkey

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// ZKey represents a ZKey file structure
type ZKey struct {
	// Header section
	Magic            [4]byte // "znkey"
	Version          uint32  // 1
	NumberOfSections uint32  // 2

	// Section 1: Protocol header
	ProtocolID uint32 // 1 for Groth16

	// Section 2: Curve parameters
	N8q        uint32   // Size of base field elements (32 bytes for BN254)
	Q          *big.Int // Base field modulus
	N8r        uint32   // Size of scalar field elements (32 bytes for BN254)
	R          *big.Int // Scalar field modulus
	NumVars    uint32   // Total variables in circuit
	NumPublic  uint32   // Public input variables
	DomainSize uint32   // FFT domain size
	Power      uint32   // Log2 of domain size
	
	// Internal data not serialized directly
	HElements  []fr.Element // H elements from prover

	// Key components
	VkAlpha1 bn254.G1Affine
	VkBeta1  bn254.G1Affine
	VkBeta2  bn254.G2Affine
	VkGamma2 bn254.G2Affine // This doesn't have a direct equivalent in gnark
	VkDelta1 bn254.G1Affine
	VkDelta2 bn254.G2Affine

	// Additional sections for full zkey compatibility
	IC       []bn254.G1Affine   // Section 3: IC points (verification key)
	Coeffs   []CoefficientEntry // Section 4: Constraint coefficients
	PointsA  []bn254.G1Affine   // Section 5: Points A
	PointsB1 []bn254.G1Affine   // Section 6: Points B1 (G1)
	PointsB2 []bn254.G2Affine   // Section 7: Points B2 (G2)
	PointsC  []bn254.G1Affine   // Section 8: Points C
	PointsH  []bn254.G1Affine   // Section 9: Points H (IFFT precomputation)
}

// CoefficientEntry represents a sparse R1CS constraint coefficient
type CoefficientEntry struct {
	Matrix     uint32     // Matrix identifier (0=A, 1=B, 2=C)
	Constraint uint32     // Constraint index
	Signal     uint32     // Signal/variable index
	Value      fr.Element // Montgomery form scalar value
}
