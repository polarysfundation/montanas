package montanas

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// Commit represents a validator's commit message for a block.
type Commit struct {
	Height    *big.Int
	Index     *big.Int
	BlockHash common.Hash
	Signature []byte
	Validator common.Address
}

// encodeCommit encodes a Commit into a 32 byte hash and byte array.
// The hash is the commit hash and the byte array contains the
// encoded commit data.
func (cm Commit) encodeCommit() ([32]byte, []byte) {

	// Encode commit fields into byte array
	var b [5 * 32]byte
	binary.BigEndian.PutUint64(b[0:32], cm.Height.Uint64())
	binary.BigEndian.PutUint64(b[32:64], cm.Index.Uint64())
	copy(b[64:96], cm.BlockHash[:])
	copy(b[96:128], cm.Signature)
	copy(b[128:160], cm.Validator[12:])

	// Hash encoded byte array to get commit hash
	output := sha256.Sum256(b[:])

	return output, b[:]
}

// decodeCommit decodes commit data from a byte array into a Commit.
// Returns an error if byte array is not exactly 256 bytes.
func decodeCommit(b []byte) (Commit, error) {

	// Validate byte array length
	if len(b) != 256 {
		return Commit{}, fmt.Errorf("input data must be 256 bytes")
	}

	var cm Commit

	// Decode commit fields from byte array
	cm.Height = new(big.Int).SetBytes(b[0:32])
	cm.Index = new(big.Int).SetBytes(b[32:64])
	copy(cm.BlockHash[:], b[64:96])
	copy(cm.Signature[:], b[96:128])
	copy(cm.Validator[:], b[128:160])

	return cm, nil
}
