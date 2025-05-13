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

// Serialize G1 point for zkey format (affine coordinates only)
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

	// Note: We do NOT add the Z coordinate here to match what the Rust parser expects
	// The Rust code only reads X and Y (64 bytes total) in read_g1()

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

	// Based on Rust's read_g2 method, we need to write:
	// 1. x-coordinate (64 bytes) - composed of x0 and x1, each 32 bytes
	// 2. y-coordinate (64 bytes) - composed of y0 and y1, each 32 bytes

	// Prepare component bytes with proper padding (32 bytes each)
	x0Bytes := make([]byte, 32)
	x1Bytes := make([]byte, 32)
	y0Bytes := make([]byte, 32)
	y1Bytes := make([]byte, 32)

	// Fill bytes for each component
	x0.FillBytes(x0Bytes)
	x1.FillBytes(x1Bytes)
	y0.FillBytes(y0Bytes)
	y1.FillBytes(y1Bytes)

	// Write X coordinate (64 bytes total)
	// Important: Order matters! The Rust code expects [x0, x1] (64 bytes)
	buffer.Write(x0Bytes)
	buffer.Write(x1Bytes)

	// Write Y coordinate (64 bytes total)
	// Important: Order matters! The Rust code expects [y0, y1] (64 bytes)
	buffer.Write(y0Bytes)
	buffer.Write(y1Bytes)

	// Note: We do NOT include Z coordinates to match the Rust parser expectations

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
	// This must match exactly with snarkjs AND Rust code expectations
	// Debug the magic bytes
	fmt.Printf("Writing magic bytes: %v (as string: %s)\n", zk.Magic[:], string(zk.Magic[:]))

	// Write the literal "zkey" string directly instead of using the Magic field
	buffer.Write([]byte("zkey"))
	binary.Write(buffer, binary.LittleEndian, zk.Version)
	binary.Write(buffer, binary.LittleEndian, zk.NumberOfSections)

	return buffer.Bytes()
}

// Serialize the ZKey to match the Rust ZKey structure format
// This method serializes in the exact format defined in the Rust struct
func (zk *ZKey) SerializeToZKeyBinary() []byte {
	buffer := new(bytes.Buffer)
	startPos := 0

	// Print overview of what we're serializing
	fmt.Printf("Serializing ZKey Section 2: n8q=%d, n8r=%d, numVars=%d, numPublic=%d, domainSize=%d, power=%d\n",
		zk.N8q, zk.N8r, zk.NumVars, zk.NumPublic, zk.DomainSize, zk.Power)

	// Write n8q (field element size for Q) - 4 bytes uint32
	binary.Write(buffer, binary.LittleEndian, zk.N8q)
	fmt.Printf("  Wrote n8q=%d, bytes %d-%d (4 bytes)\n", zk.N8q, startPos, buffer.Len()-1)
	startPos = buffer.Len()

	// Write q (base field modulus) - variable size (n8q bytes)
	qBytes := SerializeBigInt(zk.Q, int(zk.N8q))
	buffer.Write(qBytes)
	fmt.Printf("  Wrote Q modulus, bytes %d-%d (%d bytes)\n", startPos, buffer.Len()-1, len(qBytes))
	startPos = buffer.Len()

	// Write n8r (field element size for R) - 4 bytes uint32
	binary.Write(buffer, binary.LittleEndian, zk.N8r)
	fmt.Printf("  Wrote n8r=%d, bytes %d-%d (4 bytes)\n", zk.N8r, startPos, buffer.Len()-1)
	startPos = buffer.Len()

	// Write r (scalar field modulus) - variable size (n8r bytes)
	rBytes := SerializeBigInt(zk.R, int(zk.N8r))
	buffer.Write(rBytes)
	fmt.Printf("  Wrote R modulus, bytes %d-%d (%d bytes)\n", startPos, buffer.Len()-1, len(rBytes))
	startPos = buffer.Len()

	// Write n_vars (number of variables) - 4 bytes uint32
	binary.Write(buffer, binary.LittleEndian, zk.NumVars)
	fmt.Printf("  Wrote NumVars=%d, bytes %d-%d (4 bytes)\n", zk.NumVars, startPos, buffer.Len()-1)
	startPos = buffer.Len()

	// Write n_public (number of public inputs) - 4 bytes uint32
	binary.Write(buffer, binary.LittleEndian, zk.NumPublic)
	fmt.Printf("  Wrote NumPublic=%d, bytes %d-%d (4 bytes)\n", zk.NumPublic, startPos, buffer.Len()-1)
	startPos = buffer.Len()

	// Write domain_size - 4 bytes uint32
	binary.Write(buffer, binary.LittleEndian, zk.DomainSize)
	fmt.Printf("  Wrote DomainSize=%d, bytes %d-%d (4 bytes)\n", zk.DomainSize, startPos, buffer.Len()-1)
	startPos = buffer.Len()
	
	// Note: We don't write Power explicitly because the Rust code calculates it from domain_size

	// Write curve points - convert from affine to projective
	// Write vk_alpha_1 (G1 point) - fixed size
	g1Alpha := SerializeG1(zk.VkAlpha1)
	buffer.Write(g1Alpha)
	fmt.Printf("  Wrote VkAlpha1 (G1), bytes %d-%d (%d bytes)\n", startPos, buffer.Len()-1, len(g1Alpha))
	startPos = buffer.Len()

	// Write vk_beta_1 (G1 point) - fixed size
	g1Beta := SerializeG1(zk.VkBeta1)
	buffer.Write(g1Beta)
	fmt.Printf("  Wrote VkBeta1 (G1), bytes %d-%d (%d bytes)\n", startPos, buffer.Len()-1, len(g1Beta))
	startPos = buffer.Len()

	// Write vk_beta_2 (G2 point) - fixed size
	g2Beta := SerializeG2(zk.VkBeta2)
	buffer.Write(g2Beta)
	fmt.Printf("  Wrote VkBeta2 (G2), bytes %d-%d (%d bytes)\n", startPos, buffer.Len()-1, len(g2Beta))
	startPos = buffer.Len()

	// Write vk_gamma_2 (G2 point) - fixed size
	g2Gamma := SerializeG2(zk.VkGamma2)
	buffer.Write(g2Gamma)
	fmt.Printf("  Wrote VkGamma2 (G2), bytes %d-%d (%d bytes)\n", startPos, buffer.Len()-1, len(g2Gamma))
	startPos = buffer.Len()

	// Write vk_delta_1 (G1 point) - fixed size
	g1Delta := SerializeG1(zk.VkDelta1)
	buffer.Write(g1Delta)
	fmt.Printf("  Wrote VkDelta1 (G1), bytes %d-%d (%d bytes)\n", startPos, buffer.Len()-1, len(g1Delta))
	startPos = buffer.Len()

	// Write vk_delta_2 (G2 point) - fixed size
	g2Delta := SerializeG2(zk.VkDelta2)
	buffer.Write(g2Delta)
	fmt.Printf("  Wrote VkDelta2 (G2), bytes %d-%d (%d bytes)\n", startPos, buffer.Len()-1, len(g2Delta))

	// Summary of all point serialization sizes
	fmt.Printf("Point serialization sizes: G1=%d bytes, G2=%d bytes\n",
		len(g1Alpha), len(g2Beta))

	// Total section size
	fmt.Printf("Total section 2 size: %d bytes\n", buffer.Len())

	return buffer.Bytes()
}

// SerializeToFile writes the ZKey binary to a file
func (zk *ZKey) SerializeToFile(filePath string) error {
	// Validate that all required sections have data
	if zk.Q == nil || zk.R == nil {
		return fmt.Errorf("missing required field modulus values (Q or R)")
	}

	if zk.VkAlpha1.X.IsZero() && zk.VkAlpha1.Y.IsZero() {
		return fmt.Errorf("missing required vk_alpha_1 point")
	}

	if zk.VkBeta1.X.IsZero() && zk.VkBeta1.Y.IsZero() {
		return fmt.Errorf("missing required vk_beta_1 point")
	}

	if zk.VkBeta2.X.A0.IsZero() && zk.VkBeta2.X.A1.IsZero() &&
	   zk.VkBeta2.Y.A0.IsZero() && zk.VkBeta2.Y.A1.IsZero() {
		return fmt.Errorf("missing required vk_beta_2 point")
	}

	if zk.VkGamma2.X.A0.IsZero() && zk.VkGamma2.X.A1.IsZero() &&
	   zk.VkGamma2.Y.A0.IsZero() && zk.VkGamma2.Y.A1.IsZero() {
		return fmt.Errorf("missing required vk_gamma_2 point")
	}

	if zk.VkDelta1.X.IsZero() && zk.VkDelta1.Y.IsZero() {
		return fmt.Errorf("missing required vk_delta_1 point")
	}

	if zk.VkDelta2.X.A0.IsZero() && zk.VkDelta2.X.A1.IsZero() &&
	   zk.VkDelta2.Y.A0.IsZero() && zk.VkDelta2.Y.A1.IsZero() {
		return fmt.Errorf("missing required vk_delta_2 point")
	}

	// Check that all required sections are present
	if len(zk.IC) == 0 {
		return fmt.Errorf("section 3 (IC points) is empty")
	}

	// For Groth16, we need coefficients
	if len(zk.Coeffs) == 0 && len(zk.SValues) == 0 {
		return fmt.Errorf("section 4 (Coefficients) is empty")
	}

	if len(zk.PointsA) == 0 {
		return fmt.Errorf("section 5 (Points A) is empty")
	}

	if len(zk.PointsB1) == 0 {
		return fmt.Errorf("section 6 (Points B1) is empty")
	}

	if len(zk.PointsB2) == 0 {
		return fmt.Errorf("section 7 (Points B2) is empty")
	}

	if len(zk.PointsC) == 0 {
		return fmt.Errorf("section 8 (Points C) is empty")
	}

	if len(zk.PointsH) == 0 {
		return fmt.Errorf("section 9 (Points H) is empty")
	}

	// First create the output file to write to
	outFile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// First, prepare all section data buffers
	fmt.Println("=== Preparing all section data ===")
	headerData := zk.SerializeHeader()

	// Section 1: Protocol ID (Groth16 = 1)
	section1Buffer := new(bytes.Buffer)
	binary.Write(section1Buffer, binary.LittleEndian, uint32(1)) // Groth16 = 1
	section1Data := section1Buffer.Bytes()
	section1Size := uint64(len(section1Data))

	// Section 2: Curve parameters and verification key
	section2Data := zk.SerializeToZKeyBinary()
	section2Size := uint64(len(section2Data))

	// Section 3: IC (verification key points)
	section3Data := zk.SerializeICSection()
	section3Size := uint64(len(section3Data))

	// Section 4: Coefficients
	section4Data := zk.SerializeCoeffsSection()
	section4Size := uint64(len(section4Data))

	// Section 5: Points A
	section5Data := zk.SerializePointsASection()
	section5Size := uint64(len(section5Data))

	// Section 6: Points B1
	section6Data := zk.SerializePointsB1Section()
	section6Size := uint64(len(section6Data))

	// Section 7: Points B2
	section7Data := zk.SerializePointsB2Section()
	section7Size := uint64(len(section7Data))

	// Section 8: Points C
	section8Data := zk.SerializePointsCSection()
	section8Size := uint64(len(section8Data))

	// Section 9: Points H
	section9Data := zk.SerializePointsHSection()
	section9Size := uint64(len(section9Data))

	fmt.Println("=== Section Sizes ===")
	fmt.Printf("Header size: %d bytes\n", len(headerData))
	fmt.Printf("Section 1 (Protocol) size: %d bytes\n", section1Size)
	fmt.Printf("Section 2 (Params) size: %d bytes\n", section2Size)
	fmt.Printf("Section 3 (IC) size: %d bytes (%d points, %d bytes per point)\n", section3Size, len(zk.IC), int(section3Size))
	fmt.Printf("Section 4 (Coeffs) size: %d bytes (%d entries, %d bytes per entry)\n", section4Size, len(zk.SValues), int(section4Size)-4/len(zk.SValues))
	fmt.Printf("Section 5 (Points A) size: %d bytes (%d points)\n", section5Size, len(zk.PointsA))
	fmt.Printf("Section 6 (Points B1) size: %d bytes (%d points)\n", section6Size, len(zk.PointsB1))
	fmt.Printf("Section 7 (Points B2) size: %d bytes (%d points)\n", section7Size, len(zk.PointsB2))
	fmt.Printf("Section 8 (Points C) size: %d bytes (%d points)\n", section8Size, len(zk.PointsC))
	fmt.Printf("Section 9 (Points H) size: %d bytes (%d points)\n", section9Size, len(zk.PointsH))

	// Now write everything to the file
	fmt.Println("=== Writing file ===")

	// Write the file header
	_, err = outFile.Write(headerData)
	if err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write Section 1: Protocol ID
	err = writeSectionToFile(outFile, 1, section1Size, section1Data)
	if err != nil {
		return fmt.Errorf("failed to write section 1: %w", err)
	}

	// Write Section 2: Curve parameters
	err = writeSectionToFile(outFile, 2, section2Size, section2Data)
	if err != nil {
		return fmt.Errorf("failed to write section 2: %w", err)
	}

	// Write Section 3: IC points
	err = writeSectionToFile(outFile, 3, section3Size, section3Data)
	if err != nil {
		return fmt.Errorf("failed to write section 3: %w", err)
	}

	// Write Section 4: Coefficients
	err = writeSectionToFile(outFile, 4, section4Size, section4Data)
	if err != nil {
		return fmt.Errorf("failed to write section 4: %w", err)
	}

	// Write Section 5: Points A
	err = writeSectionToFile(outFile, 5, section5Size, section5Data)
	if err != nil {
		return fmt.Errorf("failed to write section 5: %w", err)
	}

	// Write Section 6: Points B1
	err = writeSectionToFile(outFile, 6, section6Size, section6Data)
	if err != nil {
		return fmt.Errorf("failed to write section 6: %w", err)
	}

	// Write Section 7: Points B2
	err = writeSectionToFile(outFile, 7, section7Size, section7Data)
	if err != nil {
		return fmt.Errorf("failed to write section 7: %w", err)
	}

	// Write Section 8: Points C
	err = writeSectionToFile(outFile, 8, section8Size, section8Data)
	if err != nil {
		return fmt.Errorf("failed to write section 8: %w", err)
	}

	// Write Section 9: Points H
	err = writeSectionToFile(outFile, 9, section9Size, section9Data)
	if err != nil {
		return fmt.Errorf("failed to write section 9: %w", err)
	}

	fmt.Println("=== File writing completed ===")
	return nil
}

// Helper function to write a section to file with proper header
func writeSectionToFile(file *os.File, sectionID uint32, sectionSize uint64, sectionData []byte) error {
	// Write section ID
	err := binary.Write(file, binary.LittleEndian, sectionID)
	if err != nil {
		return fmt.Errorf("failed to write section ID: %w", err)
	}

	// Write section size
	err = binary.Write(file, binary.LittleEndian, sectionSize)
	if err != nil {
		return fmt.Errorf("failed to write section size: %w", err)
	}

	// Write section data
	writedSize, err := file.Write(sectionData)
	if err != nil {
		return fmt.Errorf("failed to write section data: %w", err)
	}

	if uint64(writedSize) != sectionSize {
		return fmt.Errorf("section size is not equal by writed bytes, %d != %d", sectionSize, writedSize)
	}

	return nil
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
	fmt.Printf("Serializing Points A section with %d points\n", len(zk.PointsA))
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
