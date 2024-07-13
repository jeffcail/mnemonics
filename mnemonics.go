package mnemonics

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"math/rand"
	"strings"
)

var ErrEntropyLengthInvalid = errors.New("Entropy length must be [128, 256] and a multiple of 32 ")

var (
	last11BitsMask  = big.NewInt(2047)
	shift11BitsMask = big.NewInt(2048)
	bigOne          = big.NewInt(1)
	bigTwo          = big.NewInt(2)
	wordList        []string
	wordMap         map[string]int
	mnemonic24      = 256
	mnemonic12      = 128
)

func init() {
	setWordList(English)
}

func setWordList(en []string) {
	wordList = en
	wordMap = map[string]int{}
	for i, v := range wordList {
		wordMap[v] = i
	}
}

func validateEntropyBitSize(bitSize int) error {
	if (bitSize%32) != 0 || bitSize < 128 || bitSize > 256 {
		return ErrEntropyLengthInvalid
	}
	return nil
}

func newEntropy(bitSize int) ([]byte, error) {
	err := validateEntropyBitSize(bitSize)
	if err != nil {
		return nil, err
	}

	entropy := make([]byte, bitSize/8)
	_, err = rand.Read(entropy)
	return entropy, err
}

func computeChecksum(data []byte) []byte {
	hasher := sha256.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func padByteSlice(slice []byte, length int) []byte {
	offset := length - len(slice)
	if offset <= 0 {
		return slice
	}
	newSlice := make([]byte, length)
	copy(newSlice[offset:], slice)
	return newSlice
}

func newMnemonic(entropy []byte) (string, error) {
	entropyBitLength := len(entropy) * 8 // 132
	checksumBitLength := entropyBitLength / 32
	sentenceLength := (entropyBitLength + checksumBitLength) / 11

	err := validateEntropyBitSize(entropyBitLength)
	if err != nil {
		return "", err
	}

	// Add checksum to entropy.
	entropy = addChecksum(entropy)

	entropyInt := new(big.Int).SetBytes(entropy)

	words := make([]string, sentenceLength)

	word := big.NewInt(0)

	for i := sentenceLength - 1; i >= 0; i-- {
		word.And(entropyInt, last11BitsMask)
		entropyInt.Div(entropyInt, shift11BitsMask)

		wordBytes := padByteSlice(word.Bytes(), 2)
		u := binary.BigEndian.Uint16(wordBytes)
		words[i] = wordList[u]
	}

	return strings.Join(words, " "), nil
}

func addChecksum(data []byte) []byte {
	hash := computeChecksum(data)
	firstChecksumByte := hash[0]

	checksumBitLength := uint(len(data) / 4)

	dataBigInt := new(big.Int).SetBytes(data)
	for i := uint(0); i < checksumBitLength; i++ {
		dataBigInt.Mul(dataBigInt, bigTwo)

		if uint8(firstChecksumByte&(1<<(7-i))) > 0 {
			dataBigInt.Or(dataBigInt, bigOne)
		}
	}

	return dataBigInt.Bytes()
}

func create(biteByte int) string {
	entropy, _ := newEntropy(biteByte)
	mnemonic, _ := newMnemonic(entropy)
	return mnemonic
}

func Generate24Mnemonic() string {
	return create(mnemonic24)
}

func Generate12Mnemonic() string {
	return create(mnemonic12)
}
