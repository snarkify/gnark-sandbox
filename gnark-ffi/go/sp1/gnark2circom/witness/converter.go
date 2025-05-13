package witness

import (
	"fmt"
	"bytes"
	"encoding/binary"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// WtnsConverter converts gnark witness format to circom witness format
type WtnsConverter struct {
	// Field element size in bytes (32 for BN254)
	N8 uint32
	// Prime field modulus (scalar field for BN254)
	Q *big.Int
	// Witness values as big.Int
	Witness []*big.Int
	// Number of public inputs
	NumPublic uint32
	// Total number of witness values (including the "one" wire)
	NumWitness uint32
}


// Creates a new WtnsConverter directly from witness values
func NewWtnsConverter(witness []*big.Int, numPublic uint32) *WtnsConverter {
	return &WtnsConverter{
		N8:         32, // BN254 field element size in bytes
		Q:          fr.Modulus(),
		Witness:    witness,
		NumPublic:  numPublic,
		NumWitness: uint32(len(witness)),
	}
}

// Serializes the witness to circom witness format
func (wc *WtnsConverter) SerializeToCircomWitness() []byte {
	buffer := new(bytes.Buffer)

	// Write "wtns" magic
	buffer.WriteString("wtns")

	// Write version (2) as u32 little-endian
	binary.Write(buffer, binary.LittleEndian, uint32(2))

	// Write number of sections (2) as u32 little-endian
	binary.Write(buffer, binary.LittleEndian, uint32(2))

	// Write section 1 (header)
	// Section ID
	binary.Write(buffer, binary.LittleEndian, uint32(1))

	// Calculate section 1 size
	section1Buffer := new(bytes.Buffer)
	binary.Write(section1Buffer, binary.LittleEndian, wc.N8)

	// Write field modulus (Q)
	qBytes := make([]byte, wc.N8)
	wc.Q.FillBytes(qBytes)
	section1Buffer.Write(qBytes)

	// Write number of witness values
	binary.Write(section1Buffer, binary.LittleEndian, wc.NumWitness)

	// Write section 1 length
	binary.Write(buffer, binary.LittleEndian, uint64(section1Buffer.Len()))

	// Write section 1 data
	buffer.Write(section1Buffer.Bytes())

	// Write section 2 (witness values)
	// Section ID
	binary.Write(buffer, binary.LittleEndian, uint32(2))

	// Calculate section 2 size
	witnessSize := int(wc.N8) * int(wc.NumWitness)

	// Write section 2 length
	binary.Write(buffer, binary.LittleEndian, uint64(witnessSize))

	// Print first 100 elements of witness for verification
	fmt.Printf("Serializing witness with %d total elements\n", len(wc.Witness))
	fmt.Println("First 100 witness elements (or fewer if witness is smaller):")
	maxElements := 100
	if len(wc.Witness) < maxElements {
		maxElements = len(wc.Witness)
	}
	for i := 0; i < maxElements; i++ {
		// Print non-zero values to make it easier to see the padding
		if i < len(wc.Witness) && wc.Witness[i].String() != "0" {
			fmt.Printf("[%d]: %s\n", i, wc.Witness[i].String())
		}
	}
	// Print a summary of zero values at the end (likely padding)
	zeroCount := 0
	for i := 0; i < len(wc.Witness); i++ {
		if wc.Witness[i].String() == "0" {
			zeroCount++
		}
	}
	fmt.Printf("Total zero values in witness: %d (may include padding)\n", zeroCount)

	// Write the "one" wire (always first)
	oneBytes := make([]byte, wc.N8)
	// Set the first byte to 1, rest are 0 (little-endian format)
	oneBytes[0] = 1
	buffer.Write(oneBytes)

	// Write all witness values
	for i := 0; i < len(wc.Witness); i++ {
		elemBytes := make([]byte, wc.N8)
		// Convert to little-endian format as expected by circom
		// First create properly-sized byte slice with big.Int.Bytes() which is big-endian
		bigEndianBytes := wc.Witness[i].Bytes()

		// Then copy into the correct position in little-endian format
		for j := 0; j < len(bigEndianBytes) && j < int(wc.N8); j++ {
			elemBytes[j] = bigEndianBytes[len(bigEndianBytes)-1-j]
		}

		buffer.Write(elemBytes)
	}

	return buffer.Bytes()
}

// SerializeToFile writes the circom witness to a file
func (wc *WtnsConverter) SerializeToFile(filePath string) error {
	data := wc.SerializeToCircomWitness()
	return os.WriteFile(filePath, data, 0644)
}
