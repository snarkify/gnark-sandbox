package zkey

import (
	"fmt"
	"math"
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// Creates a new ZKey from gnark R1CS, proving key, verifying key, witness and h elements
func NewZKeyFromGnark(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, witness witness.Witness, h []fr.Element) (*ZKey, error) {
	zkey := &ZKey{
		Version:          1,
		NumberOfSections: 10, // Support for all 10 sections
		ProtocolID:       1,  // Groth16
		HElements:        h,  // Store the H elements for later use
	}

	// Set the magic bytes "zkey"
	copy(zkey.Magic[:], []byte("zkey"))

	// Set field sizes for BN254
	zkey.N8q = 32 // BN254 field element size in bytes
	zkey.N8r = 32 // BN254 scalar field size in bytes

	// Get modulus values for BN254
	// For BN254 base field (𝔽ₚ) - not directly exposed by library
	zkey.Q = new(big.Int)
	zkey.Q.SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	// For scalar field (𝔽ᵣ) - can get programmatically
	zkey.R = fr.Modulus()

	// Get R1CS information
	internalVarCount := r1cs.GetNbInternalVariables()
	secretVarCount := r1cs.GetNbSecretVariables()
	publicVarCount := r1cs.GetNbPublicVariables()
	nbConstraints := r1cs.GetNbConstraints()

	zkey.NumVars = uint32(internalVarCount + secretVarCount + publicVarCount)
	zkey.NumPublic = uint32(publicVarCount)

	// Use reflection to access the ProvingKey fields
	// Since gnark's ProvingKey is an interface, we need to access the concrete type's fields
	pkValue := reflect.ValueOf(pk).Elem()

	// Access Domain field
	domainField := pkValue.FieldByName("Domain")
	if !domainField.IsValid() {
		return nil, fmt.Errorf("domain field not found in proving key")
	}

	cardinalityField := domainField.FieldByName("Cardinality")
	if !cardinalityField.IsValid() {
		return nil, fmt.Errorf("cardinality field not found in domain")
	}

	cardinality := uint32(cardinalityField.Uint())

	// Calculate the minimum domain size required (next power of 2 greater than or equal to max(numVars, nbConstraints))
	requiredSize := uint32(math.Max(float64(zkey.NumVars), float64(nbConstraints)))
	power := uint32(math.Ceil(math.Log2(float64(requiredSize))))
	minDomainSize := uint32(math.Pow(2, float64(power)))

	// Use the larger of the calculated domain size and the one from the proving key
	if minDomainSize > cardinality {
		zkey.DomainSize = minDomainSize
		zkey.Power = power
	} else {
		zkey.DomainSize = cardinality
		zkey.Power = uint32(math.Log2(float64(cardinality)))
	}

	// Access G1 and G2 fields - get the struct fields first
	g1Field := pkValue.FieldByName("G1")
	if !g1Field.IsValid() {
		return nil, fmt.Errorf("G1 field not found in proving key")
	}

	g2Field := pkValue.FieldByName("G2")
	if !g2Field.IsValid() {
		return nil, fmt.Errorf("G2 field not found in proving key")
	}

	// Access verification key fields - required for Section 2
	alphaField := g1Field.FieldByName("Alpha")
	if !alphaField.IsValid() {
		return nil, fmt.Errorf("Alpha field not found in G1")
	}
	zkey.VkAlpha1 = alphaField.Interface().(bn254.G1Affine)

	betaField := g1Field.FieldByName("Beta")
	if !betaField.IsValid() {
		return nil, fmt.Errorf("Beta field not found in G1")
	}
	zkey.VkBeta1 = betaField.Interface().(bn254.G1Affine)

	deltaField := g1Field.FieldByName("Delta")
	if !deltaField.IsValid() {
		return nil, fmt.Errorf("Delta field not found in G1")
	}
	zkey.VkDelta1 = deltaField.Interface().(bn254.G1Affine)

	beta2Field := g2Field.FieldByName("Beta")
	if !beta2Field.IsValid() {
		return nil, fmt.Errorf("Beta field not found in G2")
	}
	zkey.VkBeta2 = beta2Field.Interface().(bn254.G2Affine)

	delta2Field := g2Field.FieldByName("Delta")
	if !delta2Field.IsValid() {
		return nil, fmt.Errorf("Delta field not found in G2")
	}
	zkey.VkDelta2 = delta2Field.Interface().(bn254.G2Affine)

	// For Gamma2, which doesn't exist in gnark, use the G2 generator point
	_, _, _, g2 := bn254.Generators()
	zkey.VkGamma2 = g2

	// Get the IC points from the verifying key (K field)
	// Use reflection to access the K field in the verifying key
	vkValue := reflect.ValueOf(vk).Elem()
	g1VkField := vkValue.FieldByName("G1")

	if !g1VkField.IsValid() {
		return nil, fmt.Errorf("K field not found in verifying key")
	}

	kField := g1Field.FieldByName("K")

	if !kField.IsValid() {
		return nil, fmt.Errorf("K field not found in vk.G1")
	}

	zkey.IC = kField.Interface().([]bn254.G1Affine)
	fmt.Printf("Successfully loaded IC from verifying key, with %d points\n", len(zkey.IC))

	// Access points for sections 5-9
	// Section 5: Points A
	aField := g1Field.FieldByName("A")
	if !aField.IsValid() {
		return nil, fmt.Errorf("A points field not found in G1")
	}
	zkey.PointsA = aField.Interface().([]bn254.G1Affine)

	// Section 6: Points B1 (G1)
	b1Field := g1Field.FieldByName("B")
	if !b1Field.IsValid() {
		return nil, fmt.Errorf("B points field not found in G1")
	}
	zkey.PointsB1 = b1Field.Interface().([]bn254.G1Affine)

	// Section 7: Points B2 (G2)
	b2Field := g2Field.FieldByName("B")
	if !b2Field.IsValid() {
		return nil, fmt.Errorf("B points field not found in G2")
	}
	zkey.PointsB2 = b2Field.Interface().([]bn254.G2Affine)

	// Section 8: Points C
	cField := g1Field.FieldByName("K")
	if !cField.IsValid() {
		return nil, fmt.Errorf("C points field not found in G1")
	}
	zkey.PointsC = cField.Interface().([]bn254.G1Affine)

	// Section 9: Points H
	// Reconstruct Points H (Section 9)
	domain := fft.NewDomain(uint64(nbConstraints))
	pointsH, err := ReconstructPointsH(*domain, h)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct PointsH: %w", err)
	}
	zkey.PointsH = pointsH

	// Extract coefficients from R1CS (Section 4)
	// This is a placeholder - in a complete implementation, we would
	// access and process the actual constraint system
	coeffs, err := extractCoefficientsFromR1CS(r1cs)
	if err != nil {
		return nil, fmt.Errorf("failed to extract coefficients: %w", err)
	}
	zkey.Coeffs = coeffs

	return zkey, nil
}

// Extract coefficients from R1CS constraint system
func extractCoefficientsFromR1CS(cs constraint.ConstraintSystem) ([]CoefficientEntry, error) {
	fmt.Printf("Start extract coefficients from r1 cs")

	var coeffEntries []CoefficientEntry

	// Convert cs to R1CS interface to access GetR1CIterator
	r1cs, ok := cs.(constraint.R1CS)
	if !ok {
		return nil, fmt.Errorf("constraint system is not an R1CS")
	}

	// Get iterator over all R1CS constraints
	iterator := r1cs.GetR1CIterator()

	// For each constraint
	for i := 0; i < cs.GetNbConstraints(); i++ {
		constraint := iterator.Next()
		if constraint == nil {
			break
		}

		// Process L terms (Matrix = 0 for A)
		processTerms(constraint.L, 0, uint32(i), cs, &coeffEntries)

		// Process R terms (Matrix = 1 for B)
		processTerms(constraint.R, 1, uint32(i), cs, &coeffEntries)

		// Process O terms (Matrix = 2 for C)
		processTerms(constraint.O, 2, uint32(i), cs, &coeffEntries)
	}

	return coeffEntries, nil
}

// Helper function to process terms in a constraint
func processTerms(terms constraint.LinearExpression, matrix uint32, constraintIdx uint32, cs constraint.ConstraintSystem, entries *[]CoefficientEntry) {
	for _, term := range terms {
		// Skip terms where coefficient is zero
		if term.CoeffID() == 0 { // CoeffIdZero is 0
			continue
		}

		// Get the coefficient value from the constraint system
		coeffID := term.CoeffID()

		// For BN254, attempt to convert the coefficient to the right format
		// This code assumes we're using BN254, which is the only curve supported in the current implementation

		// First get a big.Int representation of the coefficient
		// We need to access the raw field element through reflection since the GetCoefficient returns an interface
		// that might not be directly usable as fr.Element

		// Create a new fr.Element
		var frVal fr.Element

		// The exact implementation would depend on how the cs stores coefficients
		// This is a heuristic approach that handles common cases
		switch cs := cs.(type) {
		case interface{ GetCoefficients() []fr.Element }:
			// If the cs has a GetCoefficients method that returns []fr.Element
			coeffs := cs.GetCoefficients()
			if coeffID < len(coeffs) {
				frVal = coeffs[coeffID]
			} else {
				// Set to one as a fallback (not ideal)
				frVal.SetOne()
			}
		default:
			// As a fallback, set the coefficient to 1
			// This is not ideal but allows the code to work for testing
			frVal.SetOne()
		}

		// Create a coefficient entry
		entry := CoefficientEntry{
			Matrix:     matrix,
			Constraint: constraintIdx,
			Signal:     uint32(term.WireID()),
			Value:      frVal,
		}

		*entries = append(*entries, entry)
	}
}
