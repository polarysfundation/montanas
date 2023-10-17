package montanas

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/sha3"
)

// State represents the Montanas state data structure in Go.
type State struct {
	RoundId          *big.Int
	Height           *big.Int
	BlockHash        [32]byte
	ExtraData        [32]byte
	NewCommit        [32]byte
	LastCommit       [32]byte
	MerkleRoot       [32]byte
	CurrentValidator common.Address
}

// encodeState serializes the State struct into a byte array.
// It encodes each field of the State into a specific position
// in the byte array using binary encoding and copy operations.
// The resulting byte array contains all the state data packed
// into a format that can be efficiently stored or transmitted.
func (ss State) encodeState() []byte {
	_roundId := ss.RoundId
	_height := ss.Height
	_blockHash := ss.BlockHash
	_extraData := ss.ExtraData
	_newCommit := ss.NewCommit
	_lastCommit := ss.LastCommit
	_merkleRoot := ss.MerkleRoot
	_currentValidator := ss.CurrentValidator

	b := make([]byte, 8*32)

	binary.LittleEndian.PutUint64(b[0:8], _roundId.Uint64())
	binary.LittleEndian.PutUint64(b[8:16], _height.Uint64())
	copy(b[16:48], _blockHash[:])
	copy(b[48:80], _extraData[:])
	copy(b[80:112], _newCommit[:])
	copy(b[112:144], _lastCommit[:])
	copy(b[144:176], _merkleRoot[:])
	copy(b[176:196], _currentValidator[:])

	return b
}

// verifyMerkleProof verifies a Merkle proof for a leaf node against a Merkle root.
// It takes a Merkle tree, root hash, and leaf hash as input.
// It computes the leaf hash up to the root, verifying sibling hashes along the way.
// Returns true if the computed root matches the input root.
func verifyMerkleProof(merkleTree [][32]byte, merkleRoot [32]byte, leaf [32]byte) bool {
	computedHash := leaf

	for _, siblingHash := range merkleTree {
		if computedHash == siblingHash {
			// Este nodo es el hermano del nodo calculado
			continue
		}

		var combinedData []byte
		if bytes.Compare(computedHash[:], siblingHash[:]) < 0 {
			combinedData = append(computedHash[:], siblingHash[:]...)
		} else {
			combinedData = append(siblingHash[:], computedHash[:]...)
		}

		computedHash = sha256.Sum256(combinedData)
	}

	return bytes.Equal(computedHash[:], merkleRoot[:])
}

// decodeAddressArray decodes a byte array containing concatenated address byte slices into a slice of common.Address values.
// It divides the input byte slice into 32 byte chunks, copies each chunk into a separate common.Address, and returns the resulting slice.
func decodeAddressArray(a []byte) []common.Address {
	len := len(a) / 32
	b := make([]common.Address, len)

	for i := 0; i < len; i++ {
		var addr common.Address
		copy(addr[:], a[i*32:(i+1)*32])
		b[i] = addr
	}

	return b
}

// getMerkleTree constructs a Merkle tree for the given validators and coinbase,
// returning the tree as a slice of 32-byte hashes. The tree is constructed bottom-up
// starting from the validators, with each parent being the hash of its combined children.
// The root of the tree is populated with the provided merkleRoot.
func getMerkleTree(coinbase common.Address, merkleRoot [32]byte, validators []common.Address) [][32]byte {
	if len(validators) == 0 {
		panic("Validators array must not be empty")
	}

	treeHeight := calculateTreeHeight(len(validators))
	treeSize := (1 << treeHeight) - 1

	tree := make([][32]byte, treeSize+1)
	tree[0] = merkleRoot

	currentIndex := treeSize
	validatorIndex := 0

	for level := uint64(0); level < treeHeight; level++ {
		levelSize := 1 << level

		for i := uint64(0); i < uint64(levelSize); i++ {
			if currentIndex == 0 {
				// Hemos llegado a la raíz del árbol
				break
			}

			validatorHash := sha3.Sum256(append(coinbase.Bytes(), validators[validatorIndex].Bytes()...))
			siblingIndex := currentIndex - 1
			if currentIndex%2 == 0 {
				siblingIndex = currentIndex + 1
			}

			combinedData := append(tree[siblingIndex][:], validatorHash[:]...)
			tree[currentIndex] = sha256.Sum256(combinedData)
			currentIndex = (currentIndex - 1) / 2 // Movemos hacia arriba en el árbol
			validatorIndex++
		}
	}

	return tree
}

// calculateTreeHeight calculates the height of a Merkle tree
// needed to contain the given number of validators. It uses
// big.Int math to iteratively divide the validator count in
// half, incrementing the height, until the count reaches 1.
func calculateTreeHeight(validatorCount int) uint64 {
	height := new(big.Int).SetUint64(0)
	temp := new(big.Int).SetUint64(uint64(validatorCount))

	one := new(big.Int).SetUint64(1)

	for temp.Cmp(one) > 0 {
		// Redondeo hacia arriba
		temp.Add(temp, one)
		temp.Div(temp, big.NewInt(2))
		height.Add(height, one)
	}

	return height.Uint64()
}

// decodeState decodes the given byte slice into a State struct.
// It returns the decoded State and an error if the input is not the correct length.
func decodeState(ss []byte) (State, error) {
	// Check if the input is the correct length
	if len(ss) != 256 {
		return State{}, fmt.Errorf("Los datos de entrada deben tener una longitud de 256 bytes")
	}

	// Create a new State struct
	var sc State

	// Decode the RoundId
	sc.RoundId = new(big.Int).SetBytes(ss[0:32])

	// Decode the Height
	sc.Height = new(big.Int).SetBytes(ss[32:64])

	// Copy the BlockHash
	copy(sc.BlockHash[:], ss[16:48])

	// Copy the ExtraData
	copy(sc.ExtraData[:], ss[48:80])

	// Copy the NewCommit
	copy(sc.NewCommit[:], ss[80:112])

	// Copy the LastCommit
	copy(sc.LastCommit[:], ss[112:144])

	// Copy the MerkleRoot
	copy(sc.MerkleRoot[:], ss[144:176])

	// Copy the CurrentValidator
	copy(sc.CurrentValidator[:], ss[176:192])

	return sc, nil
}
