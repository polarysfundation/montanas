package montanas

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// MontanasProtocol implements the core consensus logic for the
// Montanas protocol.
type MontanasProtocol struct{}

// verifyCommit verifies that a commit is valid against a provided state.
// It returns true if the commit is valid, false otherwise.
func (protocol *MontanasProtocol) verifyCommit(commitByte []byte, commitHash [32]byte, stateByte []byte) bool {

	// Decode commit from bytes
	cm, err := decodeCommit(commitByte)
	if err != nil {
		fmt.Println("Error decoding commit:", err)
		return false
	}

	// Decode state from bytes
	s, err := decodeState(stateByte)
	if err != nil {
		fmt.Println("Error decoding state:", err)
		return false
	}

	// Encode commit to get expected hash
	_commit, _b := cm.encodeCommit()

	if !bytes.Equal(_commit[:], commitHash[:]) {
		return false
	}

	// Compare commit byte hashes
	hash1 := sha256.Sum256(_b)
	hash2 := sha256.Sum256(commitByte)
	if !bytes.Equal(hash1[:], hash2[:]) {
		return false
	}

	// Validate commit fields match state
	if _commit != s.NewCommit &&
		s.CurrentValidator != cm.Validator &&
		s.Height != cm.Height {
		return false
	}

	return true
}

// verifyState verifies a state is valid against a commit and validator set.
// It returns true if the state is valid, false otherwise.
func (protocol *MontanasProtocol) verifyState(stateByte []byte, commitByte []byte, validators []byte) bool {

	// Decode state
	s, err := decodeState(stateByte)
	if err != nil {
		fmt.Println("Error decoding state:", err)
		return false
	}

	// Decode commit
	c, err := decodeCommit(commitByte)
	if err != nil {
		fmt.Println("Error decoding commit:", err)
		return false
	}

	// Decode validator addresses
	v := decodeAddressArray(validators)

	// Assign coinbase
	_coinbase := s.CurrentValidator

	// Verify merkle root
	merkleroot_ := s.MerkleRoot
	leaf := crypto.Keccak256Hash([]byte(_coinbase.String()))

	tree := getMerkleTree(_coinbase, merkleroot_, v)

	// Assign validator index
	var index *big.Int
	for i, addr := range v {
		if addr == _coinbase {
			index = big.NewInt(int64(i))
		}
	}

	// Verify merkle proof
	checkProof := verifyMerkleProof(tree, merkleroot_, leaf)

	// Run commit verification
	validCommit := protocol.verifyCommit(commitByte, s.NewCommit, stateByte)

	// Validate state fields
	return (c.Index == index &&
		checkProof &&
		validCommit &&
		s.Height == c.Height &&
		s.BlockHash == c.BlockHash &&
		s.LastCommit != s.NewCommit)

}
