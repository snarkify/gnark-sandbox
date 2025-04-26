package witness

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
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

// Creates a new WtnsConverter from a gnark witness
func NewWtnsConverterFromGnark(w witness.Witness, r1cs constraint.ConstraintSystem) (*WtnsConverter, error) {
	// Get witness information from gnark
	wValue := reflect.ValueOf(w).Elem()
	nbPublicField := wValue.FieldByName("nbPublic")

	if !nbPublicField.IsValid() {
		return nil, fmt.Errorf("could not access nbPublic field in witness")
	}

	nbPublic := nbPublicField.Uint()

	// Extract the raw witness values and convert to fr.Element slice
	// This depends on the exact structure of the witness, which might vary by curve
	// For BN254, we'll need to extract the vector as fr.Element
	rawWitness, err := extractWitnessValues(w)
	if err != nil {
		return nil, fmt.Errorf("error extracting witness values: %v", err)
	}

	// Create the converter
	converter := &WtnsConverter{
		N8:         32, // BN254 field element size in bytes
		Q:          fr.Modulus(),
		Witness:    rawWitness,
		NumPublic:  uint32(nbPublic),
		NumWitness: uint32(len(rawWitness) + 1), // +1 for the "one" wire
	}

	return converter, nil
}

// Helper to extract witness values as []*big.Int slice
func extractWitnessValues(w witness.Witness) ([]*big.Int, error) {
	// pull the raw vector via the public API
	vecIfc := w.Vector()
	elems, ok := vecIfc.(fr.Vector)
	if !ok {
		return nil, fmt.Errorf("could not assert witness vector type: %T", vecIfc)
	}
	// convert each fr.Element → *big.Int
	out := make([]*big.Int, len(elems))
	for i, e := range elems {
		out[i] = new(big.Int)
		e.BigInt(out[i])
	}
	return out, nil
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
