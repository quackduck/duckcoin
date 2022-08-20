package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

type Address struct {
	Emoji string `json:",omitempty"`
	Text  string `json:",omitempty"`
	bytes [addrBytesLen]byte
}

// TODO: implement the custom json marshaller interfaces so that addr.bytes is automatically populated

var (
	emojiCoder = encoding{set: emoji, dataLen: addrBytesLen}
	textCoder  = encoding{set: []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), dataLen: addrBytesLen}
)

const (
	addrBytesLen           = 24
	checksumLen            = 4
	textAddressPrefixChar  = 'Q'
	emojiAddressPrefixChar = '🦆'
	//versionChar               = '0'
)

func (a *Address) UnmarshalJSON(bytes []byte) error {
	type address Address // prevent infinite unmarshal loop
	addr := address{}
	err := json.Unmarshal(bytes, &addr)
	if err != nil {
		return err
	}
	//fmt.Println(addr, []rune(addr.Emoji), len([]rune(addr.Emoji)))
	if len(addr.Emoji) > 0 || len(addr.Text) > 0 {
		emojiBytes, err := EmojiToBytes(addr.Emoji)
		if err != nil {
			return err
		}
		textBytes, err := TextToBytes(addr.Text)
		if err != nil {
			return err
		}
		if textBytes != emojiBytes {
			return errors.New("inconsistent address: decoding of emoji is not the same as the decoding of text")
		}
		addr.bytes = textBytes
	} else {
		var b [addrBytesLen]byte
		addr.bytes = b
	}
	//fmt.Println(addr, Address(addr))
	*a = Address(addr)
	return nil
}

// KeyToAddress derives a Duckcoin Address from a Duckcoin Public Key
func KeyToAddress(key string) Address {
	return BytesToAddress(sliceToAddrBytes(addChecksum(
		DoubleShasumBytes([]byte(key))[:20], // Truncation is fine. SHA256 is designed to be comparable to a random oracle and the US Government itself is okay with it: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf page 32 (section 7)
	)))
}

func EmojiOrTextToAddress(addr string) (Address, error) {
	if addr[0] == byte(textAddressPrefixChar) {
		return TextToAddress(addr)
	} else {
		return EmojiToAddress(addr)
	}
}

func EmojiToBytes(emoji string) ([addrBytesLen]byte, error) {
	var result [addrBytesLen]byte
	slice, err := emojiCoder.Decode(string([]rune(emoji)[1:]))
	if err != nil {
		return result, err
	}
	copy(result[:], slice)
	return result, nil
}

func EmojiToAddress(emoji string) (Address, error) {
	bytes, err := EmojiToBytes(emoji)
	if err != nil {
		return Address{}, err
	}
	return BytesToAddress(bytes), nil
}

func TextToBytes(text string) ([addrBytesLen]byte, error) {
	var result [addrBytesLen]byte
	slice, err := textCoder.Decode(string([]rune(text)[1:])) // remove first char: the prefix
	if err != nil {
		return result, err
	}
	copy(result[:], slice)
	return result, nil
}

func TextToAddress(text string) (Address, error) {
	bytes, err := TextToBytes(text)
	if err != nil {
		return Address{}, err
	}
	return BytesToAddress(bytes), nil
}

func BytesToAddress(b [addrBytesLen]byte) Address {
	addr := Address{
		bytes: b,
	}
	addr.Text = string(textAddressPrefixChar) + textCoder.Encode(addr.bytes[:]) // len(base64(20 + 4 bytes)) + len("q" + versionChar) = 24 * 4/3 + 2 = 34 len addrs
	addr.Emoji = string(emojiAddressPrefixChar) + emojiCoder.Encode(addr.bytes[:])
	return addr
}

func sliceToAddrBytes(addrSlice []byte) [addrBytesLen]byte {
	var arr [addrBytesLen]byte
	copy(arr[:], addrSlice)
	return arr
}

func addChecksum(data []byte) []byte {
	dataCopy := make([]byte, len(data), cap(data))
	copy(dataCopy, data) // don't modify original data

	hash := DoubleShasumBytes(data)
	return append(dataCopy, hash[:checksumLen]...)
}

func verifyChecksum(data []byte) bool {
	if len(data) < checksumLen { // == checksumLen is fine
		return false
	}
	b := string(data) == string(addChecksum(data[:len(data)-checksumLen]))
	return b // hack to compare byte slices by byte values
}

// IsValid verifies the checksum built into addresses, and checks the address format
func (a *Address) IsValid() error {
	fromEmoji, err := EmojiToAddress(a.Emoji)
	if err != nil {
		return err
	}
	fromText, err := TextToAddress(a.Text)
	if err != nil {
		return err
	}
	fromBytes := BytesToAddress(a.bytes)

	if !(fromBytes == fromText && fromText == fromEmoji) {
		return errors.New("invalid address: inconsistent formats: " + fmt.Sprint(a))
	}

	if !verifyChecksum(fromText.bytes[:]) {
		return errors.New("invalid address: checksum verification failed: " + fmt.Sprint(a))
	}
	return nil
}

type encoding struct {
	set []rune
	// dataLen is the length of the byte data used. In duckcoin, this is always 24.
	dataLen int
}

func (e *encoding) Encode(data []byte) string {
	convertedBase := toBase(new(big.Int).SetBytes(data), "", e.set)
	// repeat emoji[0] is to normalize result length. 0 because that char has zero value in the set
	return strings.Repeat(string(e.set[0]), e.EncodedLen()-len([]rune(convertedBase))) + convertedBase
}

func (e *encoding) Decode(data string) ([]byte, error) {
	if len([]rune(data)) != e.EncodedLen() {
		return nil, errors.New("could not decode: invalid length of data: " + data)
	}
	num, err := fromBase(data, e.set)
	if err != nil {
		return nil, err
	}
	return num.FillBytes(make([]byte, e.dataLen)), nil
}

func (e *encoding) EncodedLen() int {
	return int(math.Ceil(
		float64(e.dataLen) * math.Log2(256) / math.Log2(float64(len(e.set))),
	))
}

//func encodeEmojiAddress(addr [addrBytesLen]byte) string {
//	return emojiCoder.Encode(addr[:])
//	//convertedBase := toBase(new(big.Int).SetBytes(addr[:]), "", emoji)
//	//// repeat emoji[0] is to normalize result length. 0 because that char has zero value in the set
//	//return strings.Repeat(string(emoji[0]), emojiLen-len([]rune(convertedBase))) + convertedBase
//}

func toBase(num *big.Int, buf string, set []rune) string {
	base := int64(len(set))
	div, rem := new(big.Int), new(big.Int)
	div.QuoRem(num, big.NewInt(base), rem)
	if div.Cmp(big.NewInt(0)) != 0 {
		buf += toBase(div, buf, set)
	}
	return buf + string(set[rem.Uint64()])
}

//func decodeEmojiAddress(emojiAddr string) ([addrBytesLen]byte, error) {
//	var result [addrBytesLen]byte
//
//	slice, err := emojiCoder.Decode(string([]rune(emojiAddr)[1:])) // remove prefix
//	if err != nil {
//		return result, err
//	}
//	copy(result[:], slice)
//	return result, nil
//}

func fromBase(enc string, set []rune) (*big.Int, error) {
	result := new(big.Int)
	setlen := len(set)
	encRune := []rune(enc)
	numOfDigits := len(encRune)
	for i := 0; i < numOfDigits; i++ {
		mult := new(big.Int).Exp( // setlen ^ numOfDigits-i-1 = the "place value"
			big.NewInt(int64(setlen)),
			big.NewInt(int64(numOfDigits-i-1)),
			nil,
		)
		idx := findRuneIndex(encRune[i], set)
		if idx == -1 {
			return nil, errors.New("could not decode " + enc + ": rune " + string(encRune[i]) + " is not in charset")
		}
		mult.Mul(mult, big.NewInt(idx)) // multiply "place value" with the digit at spot i
		result.Add(result, mult)
	}
	return result, nil
}

// findRuneIndex returns the index of rune r in slice a, or -1 if not found
func findRuneIndex(r rune, a []rune) int64 {
	for i := range a {
		if a[i] == r {
			return int64(i)
		}
	}
	return -1
}
