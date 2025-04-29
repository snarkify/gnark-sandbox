package zkey

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Helper function to convert from Montgomery to standard representation
func FromMontgomery(element fr.Element) *big.Int {
	// The BigInt method already handles the conversion from Montgomery form to
	// standard representation by calling internal fromMont() method
	bigInt := new(big.Int)
	element.BigInt(bigInt)
	return bigInt
}

// Helper function to convert from standard to Montgomery representation
func ToMontgomery(value *big.Int) fr.Element {
	var element fr.Element
	element.SetBigInt(value)
	return element
}

// Serialize G1 point for zkey format (converts from affine to projective)
func SerializeG1(point bn254.G1Affine) []byte {
	// Convert from Montgomery form to standard form
	buffer := new(bytes.Buffer)

	x := new(big.Int)
	y := new(big.Int)

	// BigInt already handles conversion from Montgomery representation
	point.X.BigInt(x)
	point.Y.BigInt(y)

	// Serialize X (32 bytes) - ensure proper padding to exactly 32 bytes
	xBytes := make([]byte, 32)
	x.FillBytes(xBytes)
	buffer.Write(xBytes)

	// Serialize Y (32 bytes) - ensure proper padding to exactly 32 bytes
	yBytes := make([]byte, 32)
	y.FillBytes(yBytes)
	buffer.Write(yBytes)

	// For projective, add Z=1 (32 bytes)
	// This is the standard representation expected by snarkjs
	zBytes := make([]byte, 32)
	big.NewInt(1).FillBytes(zBytes)
	buffer.Write(zBytes)

	return buffer.Bytes()
}

// Serialize G2 point for zkey format
func SerializeG2(point bn254.G2Affine) []byte {
	// Convert from Montgomery form to standard form
	buffer := new(bytes.Buffer)

	// For BN254, G2 points have complex coordinates
	// X = x0 + x1*i, Y = y0 + y1*i
	x0 := new(big.Int)
	x1 := new(big.Int)
	y0 := new(big.Int)
	y1 := new(big.Int)

	// BigInt already handles conversion from Montgomery representation
	point.X.A0.BigInt(x0)
	point.X.A1.BigInt(x1)
	point.Y.A0.BigInt(y0)
	point.Y.A1.BigInt(y1)

	// IMPORTANT: SnarkJS for BN254 expects coordinates in a SPECIFIC ORDER
	// For G2 points, the order needs to be: (x1, x0, y1, y0, z1, z0)
	// This is reversed from what might be expected
	x1Bytes := make([]byte, 32)
	x0Bytes := make([]byte, 32)
	y1Bytes := make([]byte, 32)
	y0Bytes := make([]byte, 32)
	z1Bytes := make([]byte, 32) // Z = 0 + 1i (2 components for projective)
	z0Bytes := make([]byte, 32)

	// Ensure proper padding to exactly 32 bytes for each component
	x1.FillBytes(x1Bytes)
	x0.FillBytes(x0Bytes)
	y1.FillBytes(y1Bytes)
	y0.FillBytes(y0Bytes)

	// Z = 1 for affine to projective conversion (z0=1, z1=0)
	big.NewInt(0).FillBytes(z1Bytes)
	big.NewInt(1).FillBytes(z0Bytes)

	// Write all components in SnarkJS expected order
	buffer.Write(x1Bytes)
	buffer.Write(x0Bytes)
	buffer.Write(y1Bytes)
	buffer.Write(y0Bytes)
	buffer.Write(z1Bytes)
	buffer.Write(z0Bytes)

	return buffer.Bytes()
}

// Serialize modulus for zkey format
func SerializeBigInt(n *big.Int, size int) []byte {
	bytes := make([]byte, size)
	n.FillBytes(bytes)
	return bytes
}

// Create a binary representation of the ZKey header
func (zk *ZKey) SerializeHeader() []byte {
	buffer := new(bytes.Buffer)

	// Write magic ("zkey"), version (1), and number of sections (9)
	// This must match exactly with snarkjs expectations
	buffer.Write(zk.Magic[:])
	binary.Write(buffer, binary.LittleEndian, zk.Version)
	binary.Write(buffer, binary.LittleEndian, zk.NumberOfSections)

	return buffer.Bytes()
}

// Serialize the ZKey to match the Rust ZKey structure format
// This method serializes in the exact format defined in the Rust struct
func (zk *ZKey) SerializeToZKeyBinary() []byte {
	buffer := new(bytes.Buffer)

	// Write n8q (field element size for Q) - 4 bytes uint32
	binary.Write(buffer, binary.LittleEndian, zk.N8q)

	// Write q (base field modulus) - variable size
	// Convert big.Int to byte slice, ensuring proper size
	qBytes := SerializeBigInt(zk.Q, int(zk.N8q))
	buffer.Write(qBytes)

	// Write n8r (field element size for R) - 4 bytes uint32
	binary.Write(buffer, binary.LittleEndian, zk.N8r)

	// Write r (scalar field modulus) - variable size
	rBytes := SerializeBigInt(zk.R, int(zk.N8r))
	buffer.Write(rBytes)

	// Write n_vars (number of variables) - 4 bytes uint32
	binary.Write(buffer, binary.LittleEndian, zk.NumVars)

	// Write n_public (number of public inputs) - 4 bytes uint32
	binary.Write(buffer, binary.LittleEndian, zk.NumPublic)

	// Write domain_size - 4 bytes uint32
	binary.Write(buffer, binary.LittleEndian, zk.DomainSize)

	// Write power (log2 of domain size) - 4 bytes uint32
	binary.Write(buffer, binary.LittleEndian, zk.Power)

	// Write curve points - convert from affine to projective
	// Write vk_alpha_1 (G1 point) - fixed size
	buffer.Write(SerializeG1(zk.VkAlpha1))

	// Write vk_beta_1 (G1 point) - fixed size
	buffer.Write(SerializeG1(zk.VkBeta1))

	// Write vk_beta_2 (G2 point) - fixed size
	buffer.Write(SerializeG2(zk.VkBeta2))

	// Write vk_gamma_2 (G2 point) - fixed size
	buffer.Write(SerializeG2(zk.VkGamma2))

	// Write vk_delta_1 (G1 point) - fixed size
	buffer.Write(SerializeG1(zk.VkDelta1))

	// Write vk_delta_2 (G2 point) - fixed size
	buffer.Write(SerializeG2(zk.VkDelta2))

	return buffer.Bytes()
}

// SerializeToFile writes the ZKey binary to a file
func (zk *ZKey) SerializeToFile(filePath string) error {
	// First create a complete buffer with all sections
	zkeyFile := new(bytes.Buffer)
	
	// NOTE ON SECTION NUMBERING:
	// The zkey format uses 1-based section IDs that match the section numbers.
	// Section 1 contains the protocol identifier (Groth16=1, Plonk=2, etc.)
	// Section 2 contains curve parameters and verification key data
	// Sections 3-9 contain other proof system components
	
	// Write the file header
	zkeyFile.Write(zk.SerializeHeader())

	// Write Section 1: Protocol header (Groth16 = 1) 
	// Section ID (1) - 4 bytes
	binary.Write(zkeyFile, binary.LittleEndian, uint32(1))
	// Section size - 8 bytes (protocol ID is 4 bytes)
	binary.Write(zkeyFile, binary.LittleEndian, uint64(4))
	// Protocol ID (Groth16 = 1) - 4 bytes
	// CRUCIAL: SnarkJS expects exactly 1 for Groth16
	binary.Write(zkeyFile, binary.LittleEndian, uint32(1))

	// Write Section 2: Curve parameters and verification key
	// Section ID (2) - 4 bytes
	binary.Write(zkeyFile, binary.LittleEndian, uint32(2))

	// Calculate section size
	sectionData := zk.SerializeToZKeyBinary()
	sectionSize := uint64(len(sectionData))

	// Section size - 8 bytes
	binary.Write(zkeyFile, binary.LittleEndian, sectionSize)

	// Section data
	zkeyFile.Write(sectionData)

	// Write Section 3: IC (verification key points)
	if len(zk.IC) > 0 {
		sectionData := zk.SerializeICSection()
		binary.Write(zkeyFile, binary.LittleEndian, uint32(3))
		binary.Write(zkeyFile, binary.LittleEndian, uint64(len(sectionData)))
		zkeyFile.Write(sectionData)
	}

	// Write Section 4: Coefficients
	if len(zk.Coeffs) > 0 {
		sectionData := zk.SerializeCoeffsSection()
		binary.Write(zkeyFile, binary.LittleEndian, uint32(4))
		binary.Write(zkeyFile, binary.LittleEndian, uint64(len(sectionData)))
		zkeyFile.Write(sectionData)
	}

	// Write Section 5: Points A
	if len(zk.PointsA) > 0 {
		sectionData := zk.SerializePointsASection()
		binary.Write(zkeyFile, binary.LittleEndian, uint32(5))
		binary.Write(zkeyFile, binary.LittleEndian, uint64(len(sectionData)))
		zkeyFile.Write(sectionData)
	}

	// Write Section 6: Points B1
	if len(zk.PointsB1) > 0 {
		sectionData := zk.SerializePointsB1Section()
		binary.Write(zkeyFile, binary.LittleEndian, uint32(6))
		binary.Write(zkeyFile, binary.LittleEndian, uint64(len(sectionData)))
		zkeyFile.Write(sectionData)
	}

	// Write Section 7: Points B2
	if len(zk.PointsB2) > 0 {
		sectionData := zk.SerializePointsB2Section()
		binary.Write(zkeyFile, binary.LittleEndian, uint32(7))
		binary.Write(zkeyFile, binary.LittleEndian, uint64(len(sectionData)))
		zkeyFile.Write(sectionData)
	}

	// Write Section 8: Points C
	if len(zk.PointsC) > 0 {
		sectionData := zk.SerializePointsCSection()
		binary.Write(zkeyFile, binary.LittleEndian, uint32(8))
		binary.Write(zkeyFile, binary.LittleEndian, uint64(len(sectionData)))
		zkeyFile.Write(sectionData)
	}

	// Write Section 9: Points H
	if len(zk.PointsH) > 0 {
		sectionData := zk.SerializePointsHSection()
		binary.Write(zkeyFile, binary.LittleEndian, uint32(9))
		binary.Write(zkeyFile, binary.LittleEndian, uint64(len(sectionData)))
		zkeyFile.Write(sectionData)
	}

	// Write the file to disk
	return os.WriteFile(filePath, zkeyFile.Bytes(), 0644)
}

// Serialize IC section (Section 3)
func (zk *ZKey) SerializeICSection() []byte {
	buffer := new(bytes.Buffer)
	for _, point := range zk.IC {
		buffer.Write(SerializeG1(point))
	}
	return buffer.Bytes()
}

// Serialize Coefficients section (Section 4)
func (zk *ZKey) SerializeCoeffsSection() []byte {
	buffer := new(bytes.Buffer)

	// Get the number of coefficients
	numCoeffs := len(zk.SValues)

	// Write number of coefficients
	binary.Write(buffer, binary.LittleEndian, uint32(numCoeffs))

	// Write each coefficient in the exact format expected by Rust code
	// The Rust code expects: matrix(4 bytes), constraint(4 bytes), signal(4 bytes), value(32 bytes)
	// With matrix at byte 0, constraint at bytes 4-7, signal at bytes 8-11, and value at bytes 12+
	for i := 0; i < numCoeffs; i++ {
		// Important: The Rust code expects matrix index at byte 0, but with 4 bytes allocated
		// Create a 4-byte array with the matrix value at position 0
		matrixBytes := [4]byte{byte(zk.MValues[i]), 0, 0, 0}
		buffer.Write(matrixBytes[:])

		// Write constraint index (4 bytes little-endian)
		binary.Write(buffer, binary.LittleEndian, zk.CValues[i])

		// Write signal index (4 bytes little-endian)
		binary.Write(buffer, binary.LittleEndian, zk.SValues[i])

		// Write the coefficient value in Montgomery form (32 bytes for BN254)
		// The Rust code expects this to be little-endian
		bytes := zk.Values[i].Bytes()
		buffer.Write(bytes[:])
	}

	return buffer.Bytes()
}

// Serialize Points A section (Section 5)
func (zk *ZKey) SerializePointsASection() []byte {
	buffer := new(bytes.Buffer)
	for _, point := range zk.PointsA {
		buffer.Write(SerializeG1(point))
	}
	return buffer.Bytes()
}

// Serialize Points B1 section (Section 6)
func (zk *ZKey) SerializePointsB1Section() []byte {
	buffer := new(bytes.Buffer)
	for _, point := range zk.PointsB1 {
		buffer.Write(SerializeG1(point))
	}
	return buffer.Bytes()
}

// Serialize Points B2 section (Section 7)
func (zk *ZKey) SerializePointsB2Section() []byte {
	buffer := new(bytes.Buffer)
	for _, point := range zk.PointsB2 {
		buffer.Write(SerializeG2(point))
	}
	return buffer.Bytes()
}

// Serialize Points C section (Section 8)
func (zk *ZKey) SerializePointsCSection() []byte {
	buffer := new(bytes.Buffer)
	for _, point := range zk.PointsC {
		buffer.Write(SerializeG1(point))
	}
	return buffer.Bytes()
}

// Serialize Points H section (Section 9)
func (zk *ZKey) SerializePointsHSection() []byte {
	buffer := new(bytes.Buffer)
	for _, point := range zk.PointsH {
		buffer.Write(SerializeG1(point))
	}
	return buffer.Bytes()
}

// Print ZKey info for debugging
func (zk *ZKey) PrintInfo() {
	fmt.Println("ZKey Information:")
	fmt.Printf("Magic: %s\n", zk.Magic)
	fmt.Printf("Version: %d\n", zk.Version)
	fmt.Printf("Number of Sections: %d\n", zk.NumberOfSections)
	fmt.Printf("Protocol ID: %d\n", zk.ProtocolID)
	fmt.Printf("N8q: %d bytes\n", zk.N8q)
	fmt.Printf("Q: %s\n", zk.Q.String())
	fmt.Printf("N8r: %d bytes\n", zk.N8r)
	fmt.Printf("R: %s\n", zk.R.String())
	fmt.Printf("Number of Variables: %d\n", zk.NumVars)
	fmt.Printf("Number of Public Variables: %d\n", zk.NumPublic)
	fmt.Printf("Domain Size: %d\n", zk.DomainSize)
	fmt.Printf("Power: %d\n", zk.Power)
	fmt.Printf("Number of Coefficients: %d\n", len(zk.Coeffs))

	// Print curve points
	fmt.Println("VkAlpha1: [G1 point]")
	fmt.Printf("  X: %s\n", new(big.Int).SetBytes(SerializeG1(zk.VkAlpha1)[:32]).String())
	fmt.Printf("  Y: %s\n", new(big.Int).SetBytes(SerializeG1(zk.VkAlpha1)[32:64]).String())

	fmt.Println("VkBeta1: [G1 point]")
	fmt.Printf("  X: %s\n", new(big.Int).SetBytes(SerializeG1(zk.VkBeta1)[:32]).String())
	fmt.Printf("  Y: %s\n", new(big.Int).SetBytes(SerializeG1(zk.VkBeta1)[32:64]).String())

	fmt.Println("VkBeta2: [G2 point]")
	g2Beta := SerializeG2(zk.VkBeta2)
	fmt.Printf("  X.a0: %s\n", new(big.Int).SetBytes(g2Beta[:32]).String())
	fmt.Printf("  X.a1: %s\n", new(big.Int).SetBytes(g2Beta[32:64]).String())

	fmt.Println("VkGamma2: [G2 point]")
	g2Gamma := SerializeG2(zk.VkGamma2)
	fmt.Printf("  X.a0: %s\n", new(big.Int).SetBytes(g2Gamma[:32]).String())
	fmt.Printf("  X.a1: %s\n", new(big.Int).SetBytes(g2Gamma[32:64]).String())

	fmt.Println("VkDelta1: [G1 point]")
	fmt.Printf("  X: %s\n", new(big.Int).SetBytes(SerializeG1(zk.VkDelta1)[:32]).String())
	fmt.Printf("  Y: %s\n", new(big.Int).SetBytes(SerializeG1(zk.VkDelta1)[32:64]).String())

	fmt.Println("VkDelta2: [G2 point]")
	g2Delta := SerializeG2(zk.VkDelta2)
	fmt.Printf("  X.a0: %s\n", new(big.Int).SetBytes(g2Delta[:32]).String())
	fmt.Printf("  X.a1: %s\n", new(big.Int).SetBytes(g2Delta[32:64]).String())
	
	// Print section sizes
	fmt.Printf("Section sizes:\n")
	fmt.Printf("  IC (Section 3): %d points\n", len(zk.IC))
	fmt.Printf("  Coeffs (Section 4): %d entries\n", len(zk.Coeffs))
	fmt.Printf("  PointsA (Section 5): %d points\n", len(zk.PointsA))
	fmt.Printf("  PointsB1 (Section 6): %d points\n", len(zk.PointsB1))
	fmt.Printf("  PointsB2 (Section 7): %d points\n", len(zk.PointsB2))
	fmt.Printf("  PointsC (Section 8): %d points\n", len(zk.PointsC))
	fmt.Printf("  PointsH (Section 9): %d points\n", len(zk.PointsH))
}

// Debug the coefficient section's binary format
func (zk *ZKey) DebugCoeffsSection() {
	fmt.Println("Debugging Coefficients Section (Section 4):")

	// Create a serialization of the coefficients section
	data := zk.SerializeCoeffsSection()

	// Print the total size of the section
	fmt.Printf("Total section size: %d bytes\n", len(data))

	// Read the number of coefficients from the header
	numCoeffs := binary.LittleEndian.Uint32(data[:4])
	fmt.Printf("Number of coefficients: %d\n", numCoeffs)

	// Calculate s_coef (size of each coefficient entry)
	s_coef := (len(data) - 4) / int(numCoeffs)
	fmt.Printf("Size of each coefficient entry (s_coef): %d bytes\n", s_coef)

	// Expected value based on Rust code: 4 * 3 + zk.n8r (for BN254, n8r is 32)
	expectedSCoef := 4*3 + int(zk.N8r)
	fmt.Printf("Expected s_coef based on Rust code (4*3 + n8r): %d bytes\n", expectedSCoef)

	if s_coef != expectedSCoef {
		fmt.Printf("WARNING: s_coef mismatch! The Rust code expects %d bytes per entry, but our serialized data has %d bytes per entry\n",
			expectedSCoef, s_coef)
	} else {
		fmt.Printf("s_coef matches Rust expectations ✓\n")
	}

	// Print first few coefficient entries for inspection
	maxEntriesToShow := 3
	if int(numCoeffs) < maxEntriesToShow {
		maxEntriesToShow = int(numCoeffs)
	}

	fmt.Printf("First %d coefficients from structured arrays:\n", maxEntriesToShow)
	for i := 0; i < maxEntriesToShow; i++ {
		fmt.Printf("Entry %d:\n", i)
		fmt.Printf("  Matrix: %d\n", zk.MValues[i])
		fmt.Printf("  Constraint: %d\n", zk.CValues[i])
		fmt.Printf("  Signal: %d\n", zk.SValues[i])
		frVal := zk.Values[i]
		fmt.Printf("  Value: %s\n", frVal.String())
	}

	fmt.Printf("\nFirst %d coefficients from serialized data:\n", maxEntriesToShow)
	for i := 0; i < maxEntriesToShow; i++ {
		offset := 4 + i*s_coef // Skip 4-byte header

		// Extract fields
		matrix := data[offset] // First byte of the 4-byte matrix field
		constraint := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		signal := binary.LittleEndian.Uint32(data[offset+8 : offset+12])

		// Print extracted values
		fmt.Printf("Entry %d:\n", i)
		fmt.Printf("  Offset: %d\n", offset)
		fmt.Printf("  Matrix: %d (at byte %d)\n", matrix, offset)
		fmt.Printf("  Constraint: %d (at bytes %d-%d)\n", constraint, offset+4, offset+8-1)
		fmt.Printf("  Signal: %d (at bytes %d-%d)\n", signal, offset+8, offset+12-1)
		fmt.Printf("  Value: [%d bytes starting at byte %d]\n", zk.N8r, offset+12)
	}

	// Verify the arrays have the same length
	if len(zk.SValues) != len(zk.CValues) ||
	   len(zk.SValues) != len(zk.MValues) ||
	   len(zk.SValues) != len(zk.Values) {
		fmt.Printf("WARNING: Coefficient arrays have inconsistent lengths: "+
			"s_values=%d, c_values=%d, m_values=%d, values=%d\n",
			len(zk.SValues), len(zk.CValues),
			len(zk.MValues), len(zk.Values))
	} else {
		fmt.Printf("All coefficient arrays have consistent length of %d elements ✓\n",
			len(zk.SValues))
	}
}
