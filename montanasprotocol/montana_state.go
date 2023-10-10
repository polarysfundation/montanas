package montanas

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

// State representa la estructura de datos del estado Montanas en Go.
type State struct {
	RoundId          uint64
	Height           uint64
	BlockHash        [32]byte
	ExtraData        [32]byte
	NewCommit        [32]byte
	LastCommit       [32]byte
	MerkleRoot       [32]byte
	CurrentValidator common.Address
}

func verifyHeader(ss []byte, cm []byte, validators []byte) bool {
	// Decodificar State
	s, err := decodeState(ss)
	if err != nil {
		fmt.Println("Error decoding state:", err)
		return false
	}

	commit_ := s.NewCommit

	c, err := decodeCommit(cm)
	if err != nil {
		fmt.Println("Error decoding commit:", err)
		return false
	}

	// Decodificar dirección de validators
	v := decodeAddressArray(validators)

	// Asignar _coinbase
	_coinbase := s.CurrentValidator

	// Verificar height
	merkleroot_ := s.MerkleRoot
	leaf := crypto.Keccak256Hash([]byte(_coinbase.String()))

	tree := getMerkleTree(_coinbase, merkleroot_, v)

	// Asignar index
	var index uint64
	for i, addr := range v {
		if addr == _coinbase {
			index = uint64(i)
		}
	}

	checkProof := verifyMerkleProof(tree, merkleroot_, leaf)

	return (c.Index == index &&
		checkProof &&
		verifyCommit(cm, commit_, ss) &&
		s.Height == c.Height &&
		s.BlockHash == c.BlockHash && s.LastCommit != commit_)
}

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

func decodeState(ss []byte) (State, error) {
	if len(ss) != 256 {
		return State{}, fmt.Errorf("Los datos de entrada deben tener una longitud de 256 bytes")
	}

	var sc State

	sc.RoundId = binary.BigEndian.Uint64(ss[0:8])
	sc.Height = binary.BigEndian.Uint64(ss[8:16])
	copy(sc.BlockHash[:], ss[16:48])
	copy(sc.ExtraData[:], ss[48:80])
	copy(sc.NewCommit[:], ss[80:112])
	copy(sc.LastCommit[:], ss[112:144])
	copy(sc.MerkleRoot[:], ss[144:176])
	copy(sc.CurrentValidator[:], ss[176:192])

	return sc, nil
}
