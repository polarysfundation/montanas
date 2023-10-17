package moskovskiy

import (
	"fmt"
	"math/big"
	"github.com/ethereum/go-ethereum/common"
)

// Header representa la estructura de un encabezado en Ethereum.
type Header struct {
	Height     *big.Int
	BlockHash  common.Hash
	Coinbase   common.Address
	Difficulty *big.Int
	ExtraData  common.Hash
	GasLimit   *big.Int
	ParentHash common.Hash
	Timestamp  *big.Int
}

// HeaderStorer es una estructura que almacena un encabezado como un slice de bytes.
type HeaderStorer struct {
	Header []byte
}

// decodeHeader decodifica los datos de encabezado almacenados en HeaderStorer y los devuelve como un objeto Header.
func (hs *HeaderStorer) decodeHeader() Header {
	var header Header

	header.Height = new(big.Int).SetBytes(hs.Header[0:32])
	copy(header.BlockHash[:], hs.Header[32:64])
	copy(header.Coinbase[:], hs.Header[64:96])
	header.Difficulty = new(big.Int).SetBytes(hs.Header[96:128])
	copy(header.ExtraData[:], hs.Header[128:160])
	header.GasLimit = new(big.Int).SetBytes(hs.Header[160:196])
	copy(header.ParentHash[:], hs.Header[196:228])
	header.Timestamp = new(big.Int).SetBytes(hs.Header[228:260])

	return header
}

// verifyHeader verifica la validez de un encabezado dado y devuelve el encabezado y un error en caso de problemas.
func verifyHeader(input []byte) (Header, error) {
	var hs HeaderStorer
	var header Header
	zeroAddress := common.Address{}
	zeroHash := common.Hash{}

	hs.Header = input

	header = hs.decodeHeader()
	if header.Coinbase != zeroAddress && header.BlockHash != zeroHash {
		return header, nil
	} else if header.Height.Cmp(big.NewInt(0)) == 0 {
		if header.ParentHash == zeroHash {
			return header, nil
		} else {
			return header, fmt.Errorf("invalid genesis block")
		}
	} else {
		return header, fmt.Errorf("invalid header")
	}
}
