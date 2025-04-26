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

	// Serialize all components (32 bytes each)
	// Order might need adjustment based on zkey specification
	x0Bytes := make([]byte, 32)
	x1Bytes := make([]byte, 32)
	y0Bytes := make([]byte, 32)
	y1Bytes := make([]byte, 32)
	zBytes := make([]byte, 64) // Z = 1 + 0i (2 components for projective)

	// Ensure proper padding to exactly 32 bytes for each component
	x0.FillBytes(x0Bytes)
	x1.FillBytes(x1Bytes)
	y0.FillBytes(y0Bytes)
	y1.FillBytes(y1Bytes)

	// Z = 1 for affine to projective conversion
	big.NewInt(1).FillBytes(zBytes[:32])
	big.NewInt(0).FillBytes(zBytes[32:])

	// Write all components
	buffer.Write(x0Bytes)
	buffer.Write(x1Bytes)
	buffer.Write(y0Bytes)
	buffer.Write(y1Bytes)
	buffer.Write(zBytes)

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

	// Write magic, version, and number of sections
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

	// Write the file header
	zkeyFile.Write(zk.SerializeHeader())

	// Write Section 1: Protocol header (Groth16 = 1)
	// Section ID (1) - 4 bytes
	binary.Write(zkeyFile, binary.LittleEndian, uint32(1))
	// Section size - 8 bytes (protocol ID is 4 bytes)
	binary.Write(zkeyFile, binary.LittleEndian, uint64(4))
	// Protocol ID (Groth16 = 1) - 4 bytes
	binary.Write(zkeyFile, binary.LittleEndian, zk.ProtocolID)

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

	// Write number of coefficients
	binary.Write(buffer, binary.LittleEndian, uint32(len(zk.Coeffs)))

	// Write each coefficient
	for _, coef := range zk.Coeffs {
		binary.Write(buffer, binary.LittleEndian, coef.Matrix)
		binary.Write(buffer, binary.LittleEndian, coef.Constraint)
		binary.Write(buffer, binary.LittleEndian, coef.Signal)

		// Convert value to bytes in Montgomery form
		bytes := coef.Value.Bytes()
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
}