package zkey

import (
	"fmt"
	"math"
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	bn254CS "github.com/consensys/gnark/constraint/bn254"
)

// Creates a new ZKey from gnark R1CS, proving key, verifying key, witness vector and h elements
func NewZKeyFromGnark(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, witnessVector []fr.Element, h []fr.Element) (*ZKey, error) {
	zkey := &ZKey{
		Version:          1,
		NumberOfSections: 9, // Support for 9 sections (sections 1-9)
		ProtocolID:       1, // Groth16
		HElements:        h, // Store the H elements for later use
	}

	// Set the magic bytes "zkey"
	// Debug the issue - print bytes before and after copying
	fmt.Printf("Magic bytes before: %v\n", zkey.Magic[:])
	copy(zkey.Magic[:], []byte("zkey"))
	fmt.Printf("Magic bytes after copy: %v (as string: %s)\n", zkey.Magic[:], string(zkey.Magic[:]))

	// Set field sizes for BN254
	zkey.N8q = 32 // BN254 field element size in bytes
	zkey.N8r = 32 // BN254 scalar field size in bytes

	// Get modulus values for BN254
	// For BN254 base field (𝔽ₚ) - not directly exposed by library
	// IMPORTANT: The string representation must exactly match what snarkjs expects for BN254/BN128
	zkey.Q = new(big.Int)
	zkey.Q.SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	// For scalar field (𝔽ᵣ) - must use the exact string representation expected by snarkjs
	zkey.R = new(big.Int)
	zkey.R.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

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

	// For Gamma2, which doesn't exist in gnark directly, use the G2 generator point
	// SnarkJS expects this to be the generator point for the BN254 curve
	// Generators returns (g1Jac G1Jac, g2Jac G2Jac, g1Aff G1Affine, g2Aff G2Affine)
	_, _, _, g2Aff := bn254.Generators() // g2Aff is G2Affine
	zkey.VkGamma2 = g2Aff

	// Get the IC points from the verifying key (K field)
	// Use reflection to access the K field in the verifying key
	vkValue := reflect.ValueOf(vk).Elem()
	g1VkField := vkValue.FieldByName("G1")

	if !g1VkField.IsValid() {
		return nil, fmt.Errorf("K field not found in verifying key")
	}

	kField := g1VkField.FieldByName("K")

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
	pointsA := aField.Interface().([]bn254.G1Affine)
	
	// Check if points_a needs padding to match witness length
	pointsALen := len(pointsA)
	witnessLen := len(witnessVector)
	fmt.Printf("Points A length: %d, Witness vector length: %d\n", pointsALen, witnessLen)
	
	if witnessLen > pointsALen {
		// Extend points_a with zero/infinity points for debugging
		paddedPointsA := make([]bn254.G1Affine, witnessLen)
		copy(paddedPointsA, pointsA)
		
		// Add zero/infinity points for padding
		// (the default zero value for G1Affine is the point at infinity)
		
		fmt.Printf("Padded points_a from %d to %d elements\n", pointsALen, witnessLen)
		zkey.PointsA = paddedPointsA
	} else {
		zkey.PointsA = pointsA
	}

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

	fmt.Printf("Start Points H")
	zField := g1Field.FieldByName("Z")
	if !zField.IsValid() {
		return nil, fmt.Errorf("Alpha field not found in G1")
	}
	zkey.PointsH = zField.Interface().([]bn254.G1Affine)

	fmt.Printf("Start Coeffs")
	// Extract coefficients from R1CS (Section 4)
	// Process and structure them according to Rust's expected format
	coeffData, err := extractCoefficientsFromR1CS(r1cs)
	if err != nil {
		return nil, fmt.Errorf("failed to extract coefficients: %w", err)
	}
	// Convert structured data to flat array format for backward compatibility
	zkey.Coeffs = coeffData.ToEntries()

	// Also populate the separate arrays that we'll use for serialization
	// This matches what the Rust ZKeyCache expects
	zkey.SValues = coeffData.SValues
	zkey.CValues = coeffData.CValues
	zkey.MValues = coeffData.MValues
	zkey.Values = coeffData.Values

	// Debug the coefficients section to ensure it matches what Rust expects
	fmt.Println("==== Validating coefficient section format for Rust compatibility ====")
	zkey.DebugCoeffsSection()
	fmt.Println("==== End of validation ====")

	return zkey, nil
}

// Extract coefficients from R1CS constraint system
// Returns structured coefficient data that matches Rust's expectation
func extractCoefficientsFromR1CS(cs constraint.ConstraintSystem) (CoefficientsData, error) {
	fmt.Printf("Extracting coefficients from R1CS\n")

	// Initialize the structured coefficient data
	coeffData := CoefficientsData{}

	// Convert cs to R1CS interface to access GetR1CIterator
	r1cs, ok := cs.(constraint.R1CS)
	if !ok {
		return CoefficientsData{}, fmt.Errorf("constraint system is not an R1CS")
	}

	// Get underlying implementation to access coefficient table
	bn254CS, ok := cs.(*bn254CS.SparseR1CS)
	if !ok {
		return CoefficientsData{}, fmt.Errorf("expected *cs.system type, got %T", cs)
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
		if err := processTermsStructured(constraint.L, 0, uint32(i), bn254CS, &coeffData); err != nil {
			return CoefficientsData{}, fmt.Errorf("error processing L terms for constraint %d: %w", i, err)
		}

		// Process R terms (Matrix = 1 for B)
		if err := processTermsStructured(constraint.R, 1, uint32(i), bn254CS, &coeffData); err != nil {
			return CoefficientsData{}, fmt.Errorf("error processing R terms for constraint %d: %w", i, err)
		}

		// Note: In snarkjs format, we only include A and B matrices (0 and 1)
		// We don't process O terms (C matrix) as they're handled differently
	}

	// Verify all arrays have the same length
	numCoeffs := len(coeffData.SValues)
	if numCoeffs == 0 {
		return CoefficientsData{}, fmt.Errorf("no coefficients extracted from R1CS")
	}

	if len(coeffData.CValues) != numCoeffs || len(coeffData.MValues) != numCoeffs || len(coeffData.Values) != numCoeffs {
		return CoefficientsData{}, fmt.Errorf("coefficient arrays have inconsistent lengths: s_values=%d, c_values=%d, m_values=%d, values=%d",
			numCoeffs, len(coeffData.CValues), len(coeffData.MValues), len(coeffData.Values))
	}

	fmt.Printf("Extracted %d coefficient entries\n", numCoeffs)
	fmt.Printf("Organized into s_values(%d), c_values(%d), m_values(%d), values(%d)\n",
		len(coeffData.SValues), len(coeffData.CValues), len(coeffData.MValues), len(coeffData.Values))

	// Validate matrix values (should be 0 for A or 1 for B)
	for i, m := range coeffData.MValues {
		if m > 1 {
			return CoefficientsData{}, fmt.Errorf("coefficient %d has invalid matrix value %d, must be 0 or 1", i, m)
		}
	}

	return coeffData, nil
}


// Helper function to process terms in a constraint
// Modifies entries in-place, returns error if any issues occur
func processTerms(terms constraint.LinearExpression, matrix uint32, constraintIdx uint32, r1cs *bn254CS.SparseR1CS, entries *[]CoefficientEntry) error {
	for _, term := range terms {
		// Skip terms where coefficient is zero
		if term.CoeffID() == 0 { // CoeffIdZero is 0
			continue
		}

		// Get the coefficient directly from the coefficient table
		coeffID := term.CoeffID()
		if int(coeffID) >= len(r1cs.Coefficients) {
			return fmt.Errorf("coefficient ID %d out of range (max %d)", coeffID, len(r1cs.Coefficients))
		}

		// Get the coefficient value from the table
		frVal := r1cs.Coefficients[coeffID]

		// Skip zero coefficients
		if frVal.IsZero() {
			continue
		}

		// Create a coefficient entry in snarkjs format
		entry := CoefficientEntry{
			Matrix:     matrix,
			Constraint: constraintIdx,
			Signal:     uint32(term.WireID()),
			Value:      frVal,
		}

		*entries = append(*entries, entry)
	}

	return nil
}

// Helper function to process terms into structured coefficient data
// Modifies coeffData in-place, returns error if any issues occur
func processTermsStructured(terms constraint.LinearExpression, matrix uint32, constraintIdx uint32, r1cs *bn254CS.SparseR1CS, coeffData *CoefficientsData) error {
	for _, term := range terms {
		// Skip terms where coefficient is zero
		if term.CoeffID() == 0 { // CoeffIdZero is 0
			continue
		}

		// Get the coefficient directly from the coefficient table
		coeffID := term.CoeffID()
		if int(coeffID) >= len(r1cs.Coefficients) {
			return fmt.Errorf("coefficient ID %d out of range (max %d)", coeffID, len(r1cs.Coefficients))
		}

		// Get the coefficient value from the table
		frVal := r1cs.Coefficients[coeffID]

		// Skip zero coefficients
		if frVal.IsZero() {
			continue
		}

		// Append values to the proper arrays
		coeffData.SValues = append(coeffData.SValues, uint32(term.WireID()))
		coeffData.CValues = append(coeffData.CValues, constraintIdx)
		coeffData.MValues = append(coeffData.MValues, matrix)
		coeffData.Values = append(coeffData.Values, frVal)
	}

	return nil
}
