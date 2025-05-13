package sp1

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	bn254cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"

	gnark2circomWitness "github.com/succinctlabs/sp1-recursion-gnark/sp1/gnark2circom/witness"
	gnark2circomZkey "github.com/succinctlabs/sp1-recursion-gnark/sp1/gnark2circom/zkey"
)

var globalMutex sync.RWMutex
var globalR1cs constraint.ConstraintSystem = groth16.NewCS(ecc.BN254)
var globalR1csInitialized = false
var globalPk groth16.ProvingKey = groth16.NewProvingKey(ecc.BN254)
var globalPkInitialized = false
var globalVk groth16.VerifyingKey = groth16.NewVerifyingKey(ecc.BN254)
var globalVkInitialized = false

func ProvePlonk(dataDir string, witnessPath string) Proof {
	// Sanity check the required arguments have been provided.
	if dataDir == "" {
		panic("dataDirStr is required")
	}
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)

	// Read the R1CS.
	scsFile, err := os.Open(dataDir + "/" + plonkCircuitPath)
	if err != nil {
		panic(err)
	}
	scs := plonk.NewCS(ecc.BN254)
	scs.ReadFrom(scsFile)
	defer scsFile.Close()

	// Read the proving key.
	pkFile, err := os.Open(dataDir + "/" + plonkPkPath)
	if err != nil {
		panic(err)
	}
	pk := plonk.NewProvingKey(ecc.BN254)
	bufReader := bufio.NewReaderSize(pkFile, 1024*1024)
	pk.UnsafeReadFrom(bufReader)
	defer pkFile.Close()

	// Read the verifier key.
	vkFile, err := os.Open(dataDir + "/" + plonkVkPath)
	if err != nil {
		panic(err)
	}
	vk := plonk.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(vkFile)
	defer vkFile.Close()

	// Read the file.
	data, err := os.ReadFile(witnessPath)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}

	// Generate the witness.
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	// Generate the proof.
	proof, err := plonk.Prove(scs, pk, witness)
	if err != nil {
		panic(err)
	}

	// Verify proof.
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	return NewSP1PlonkBn254Proof(&proof, witnessInput)
}

func ProveGroth16(dataDir string, witnessPath string) Proof {
	// Sanity check the required arguments have been provided.
	if dataDir == "" {
		panic("dataDirStr is required")
	}

	start := time.Now()
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)
	os.Setenv("GROTH16", "1")
	fmt.Printf("Setting environment variables took %s\n", time.Since(start))

	// Read the R1CS.
	globalMutex.Lock()
	if !globalR1csInitialized {
		start = time.Now()
		r1csFile, err := os.Open(dataDir + "/" + groth16CircuitPath)
		if err != nil {
			panic(err)
		}
		r1csReader := bufio.NewReaderSize(r1csFile, 1024*1024)
		globalR1cs.ReadFrom(r1csReader)
		defer r1csFile.Close()
		globalR1csInitialized = true
		fmt.Printf("Reading R1CS took %s\n", time.Since(start))
	}
	globalMutex.Unlock()

	// Read the proving key.
	globalMutex.Lock()
	if !globalPkInitialized {
		start = time.Now()
		pkFile, err := os.Open(dataDir + "/" + groth16PkPath)
		if err != nil {
			panic(err)
		}
		pkReader := bufio.NewReaderSize(pkFile, 1024*1024)
		globalPk.ReadDump(pkReader)
		defer pkFile.Close()
		globalPkInitialized = true
		fmt.Printf("Reading proving key took %s\n", time.Since(start))
	}
	globalMutex.Unlock()

	// Read the verifying key.
	globalMutex.Lock()
	if !globalVkInitialized {
		start = time.Now()
		vkFile, err := os.Open(dataDir + "/" + groth16VkPath)
		if err != nil {
			panic(err)
		}
		globalVk.ReadFrom(vkFile)
		defer vkFile.Close()
		globalVkInitialized = true
		fmt.Printf("Reading verifying key took %s\n", time.Since(start))
	}
	globalMutex.Unlock()

	start = time.Now()
	// Read the file.
	data, err := os.ReadFile(witnessPath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Reading witness file took %s\n", time.Since(start))

	start = time.Now()
	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Deserializing JSON data took %s\n", time.Since(start))

	start = time.Now()
	// Generate the witness.
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generating witness took %s\n", time.Since(start))

	start = time.Now()
	// Print debug info
	fmt.Println("=== ProveGroth16 is calling groth16.Prove with verification key initialized:", globalVkInitialized)

	// Set our intercept callback function that will be called from the Prove function
	groth16bn254.ProveInterceptCallback = func(r1cs *bn254cs.R1CS, pk *groth16bn254.ProvingKey, fullWitness []fr.Element, vk *groth16bn254.VerifyingKey, h []fr.Element) {
		fmt.Println("=== Field Arrays Size Analysis ===")

		// Print size of full witness
		fmt.Printf("fullWitness size: %d\n", len(fullWitness))

		// Points A size
		fmt.Printf("points_a size: %d\n", len(pk.G1.A))
		fmt.Printf("points_a infinity points: %d\n", pk.NbInfinityA)

		// Points B1 size
		fmt.Printf("points_b1 size: %d\n", len(pk.G1.B))

		// Count infinity points in B1
		actualInfinityCountB := 0
		for _, isInfinity := range pk.InfinityB {
			if isInfinity {
				actualInfinityCountB++
			}
		}
		fmt.Printf("points_b1 infinity points: %d\n", actualInfinityCountB)

		// Points C size
		fmt.Printf("points_c size: %d\n", len(pk.G1.K))
		fmt.Printf("points_c used range: d_scalars[%d:] (starting after public inputs)\n", r1cs.GetNbPublicVariables()+1)

		// Points B2 size
		fmt.Printf("points_b size: %d\n", len(pk.G2.B))

		// Points H size
		fmt.Printf("points_h size: %d\n", len(pk.G1.Z))
		fmt.Printf("h elements size: %d\n", len(h))

		// NumberOfSections, NumVars, NumPublic
		internalVarCount := r1cs.GetNbInternalVariables()
		secretVarCount := r1cs.GetNbSecretVariables()
		publicVarCount := r1cs.GetNbPublicVariables()

		numVars := uint32(internalVarCount + secretVarCount + publicVarCount)
		fmt.Printf("numVars: %d\n", numVars)
		fmt.Printf("numPublic: %d\n", r1cs.GetNbPublicVariables())

		fmt.Println("Converting to zkey format")

		// Create a ZKey from the R1CS, proving key, verifying key, and h elements
		// Pass the fr.Vector directly for the witness parameter
		zkeyConverter, err := gnark2circomZkey.NewZKeyFromGnark(r1cs, pk, vk, fullWitness, h)
		if err != nil {
			fmt.Printf("Error creating zkey converter: %v\n", err)
			return
		}

		// Define the path where to save the zkey file
		zkeyPath := dataDir + "/sp1_circuit.zkey"

		// Serialize to file
		err = zkeyConverter.SerializeToFile(zkeyPath)
		if err != nil {
			fmt.Printf("Error writing zkey file: %v\n", err)
			return
		}

		fmt.Printf("Zkey successfully saved to %s\n", zkeyPath)
		fmt.Println("Converting witness to circom wtns format")

		// Check if we can access the infinity info
		infinityA := pk.InfinityA
		nbInfinityA := pk.NbInfinityA

		fmt.Printf("Found InfinityA information: %d points at infinity out of %d total points\n", nbInfinityA, len(infinityA))

		//// Verify that the number of infinity points matches the actual count
		//actualInfinityCount := 0
		//for _, isInfinity := range infinityA {
		//	if isInfinity {
		//		actualInfinityCount++
		//	}
		//}
		//fmt.Printf("Actual infinity points count: %d\n", actualInfinityCount)

		//// Filter the witness vector to exclude points corresponding to infinity points
		//// This mimics what Gnark does internally before MSM
		//filteredWitness := make([]fr.Element, len(fullWitness)-int(nbInfinityA))

		//// Copy the witness values, skipping those corresponding to infinity points
		//for i, j := 0, 0; j < len(filteredWitness); i++ {
		//	if i < len(infinityA) && infinityA[i] {
		//		// Skip this point since it corresponds to an infinity point
		//		continue
		//	}

		//	if j < len(filteredWitness) && i < len(fullWitness) {
		//		filteredWitness[j] = fullWitness[i]
		//		j++
		//	}
		//}

		//fmt.Printf("Filtered witness length: %d", len(filteredWitness))

		// Convert to []*big.Int with padding to match points_a length
		bigInts := make([]*big.Int, len(fullWitness))

		// Copy existing witness values
		for i := 0; i < len(fullWitness); i++ {
			bigInts[i] = new(big.Int)
			fullWitness[i].BigInt(bigInts[i])
		}

		// Get number of public inputs from the R1CS
		numPublic := uint32(r1cs.GetNbPublicVariables())

		// Create the witness converter directly
		wtnsConverter := gnark2circomWitness.NewWtnsConverter(bigInts, numPublic)

		// Define the path where to save the wtns file
		wtnsPath := dataDir + "/sp1_witness.wtns"

		// Serialize to file
		err = wtnsConverter.SerializeToFile(wtnsPath)
		if err != nil {
			fmt.Printf("Error writing witness file: %v\n", err)
			return
		}

		fmt.Printf("Witness successfully saved to %s\n", wtnsPath)
	}

	// Generate the proof with verification key
	proof, err := groth16.Prove(globalR1cs, globalPk, globalVk, witness)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		panic(err)
	}
	fmt.Printf("Generating proof took %s\n", time.Since(start))

	return NewSP1Groth16Proof(&proof, witnessInput)
}
