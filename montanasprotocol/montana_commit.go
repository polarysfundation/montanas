package montanas

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

/* commits := make(map[[32]byte]Commit) */

// Commit representa la estructura de datos de un Commit en Go.
type Commit struct {
	Height    uint64
	Index     uint64
	BlockHash [32]byte
	Signature [32]byte
	Validator common.Address
}

func verifyCommit(b []byte, commit [32]byte, ss []byte) bool {
	var _commit [32]byte
	var _b []byte

	cm, err := decodeCommit(b)
	if err != nil {
		fmt.Println("Error decoding commit:", err)
		return false
	}

	s, err := decodeState(ss)
	if err != nil {
		fmt.Println("Error decoding state:", err)
		return false
	}

	_commit, _b = setCommit(cm)

	// Comparar _commit con commit
	if _commit != commit {
		return false
	}

	// Calcular el hash SHA256 de _b y b y compararlos
	hash1 := sha256.Sum256(_b)
	hash2 := sha256.Sum256(b)
	if !bytes.Equal(hash1[:], hash2[:]) {
		return false
	}

	if _commit != s.NewCommit &&
		s.CurrentValidator != cm.Validator && s.Height != cm.Height {
		return false
	}

	return true
}

func setCommit(cm Commit) ([32]byte, []byte) {
	_height := cm.Height
	_index := cm.Index
	_blockHash := cm.BlockHash
	_signature := cm.Signature
	_validatorBytes := cm.Validator.Bytes()

	var b [5 * 32]byte

	binary.BigEndian.PutUint64(b[0:8], _height)
	binary.BigEndian.PutUint64(b[8:16], _index)
	copy(b[16:48][:], _blockHash[:])
	copy(b[48:80][:], _signature[:])
	copy(b[80:100][:], _validatorBytes[12:]) // Copiar los últimos 20 bytes de la dirección

	output := sha256.Sum256(b[:])

	return output, b[:]
}

func decodeCommit(b []byte) (Commit, error) {
	if len(b) != 256 {
		return Commit{}, fmt.Errorf("Los datos de entrada deben tener una longitud de 256 bytes")
	}

	var cm Commit

	cm.Height = binary.BigEndian.Uint64(b[0:8])
	cm.Index = binary.BigEndian.Uint64(b[8:16])
	copy(cm.BlockHash[:], b[16:48])
	copy(cm.Signature[:], b[48:80])
	copy(cm.Validator[:], b[80:100])

	return cm, nil
}
