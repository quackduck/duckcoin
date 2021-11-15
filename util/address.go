package util

import (
	"encoding/base64"
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

//func (a Address) Equals(s string) bool {
//	return a.Emoji == s || a.Text == s
//}

// TODO: implement the custom json marshaller interfaces so that addr.bytes is automatically populated

var (
	//	len(set)^x = 256, where x is the multiplier. thus, x = log_[len](256) = log(256)/log(len)
	emojiLen = 1 + int(math.Ceil( // +1 because we want a starting duck emoji
		float64(addrBytesLen)*math.Log2(256)/math.Log2(float64(len(emoji))),
	))

	// TODO: encode to text with a custom charset too
	textLen = 1 + int(math.Ceil( // +2 because of the prefix and the version char
		float64(addrBytesLen)*4.0/3.0,
	))
)

const (
	addrBytesLen              = 24
	checksumLen               = 4
	duckcoinAddressPrefixChar = 'Q'
	//versionChar               = '0'
)

func (a *Address) UnmarshalJSON(bytes []byte) error {
	type address Address // prevent infinite unmarshall loop
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
	if addr[0] == byte(duckcoinAddressPrefixChar) {
		return TextToAddress(addr)
	} else {
		return EmojiToAddress(addr)
	}
}

func EmojiToBytes(emoji string) ([24]byte, error) {
	var result [addrBytesLen]byte
	bytes, err := decodeEmojiAddress(emoji)
	if err != nil {
		return result, err
	}
	return bytes, nil
}

func EmojiToAddress(emoji string) (Address, error) {
	bytes, err := EmojiToBytes(emoji)
	if err != nil {
		return Address{}, err
	}
	return BytesToAddress(bytes), nil
}

func TextToBytes(text string) ([24]byte, error) {
	var result [addrBytesLen]byte
	bytes, err := base64.StdEncoding.DecodeString(text[1:]) // remove first char: the prefix
	if err != nil {
		return result, err
	}
	return sliceToAddrBytes(bytes), nil
}

func TextToAddress(text string) (Address, error) {
	if len(text) != textLen {
		return Address{}, errors.New("could not decode text address: invalid length: " + text)
	}
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
	addr.Text = string(duckcoinAddressPrefixChar) + base64.StdEncoding.EncodeToString(addr.bytes[:]) // len(base64(20 + 4 bytes)) + len("q" + versionChar) = 24 * 4/3 + 2 = 34 len addrs
	addr.Emoji = encodeEmojiAddress(addr.bytes)
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

// IsAddressValid verifies the checksum built into addresses, and checks the address format
func IsAddressValid(addr Address) error {
	fromEmoji, err := EmojiToAddress(addr.Emoji)
	if err != nil {
		return err
	}
	fromText, err := TextToAddress(addr.Text)
	if err != nil {
		return err
	}
	fromBytes := BytesToAddress(addr.bytes)

	if !(fromBytes == fromText && fromText == fromEmoji) {
		return errors.New("invalid address: inconsistent formats: " + fmt.Sprint(addr))
	}

	if !verifyChecksum(fromText.bytes[:]) {
		return errors.New("invalid address: checksum verification failed: " + fmt.Sprint(addr))
	}
	return nil
}

func encodeEmojiAddress(addr [addrBytesLen]byte) string {
	convertedBase := toBase(new(big.Int).SetBytes(addr[:]), "")
	// repeat emoji[0] is to normalize result length. 0 because that char has zero value in the set
	return strings.Repeat(string(emoji[0]), emojiLen-len([]rune(convertedBase))) + convertedBase
}

func toBase(num *big.Int, buf string) string {
	base := int64(len(emoji))
	div, rem := new(big.Int), new(big.Int)
	div.QuoRem(num, big.NewInt(base), rem)
	if div.Cmp(big.NewInt(0)) != 0 {
		buf += toBase(div, buf)
	}
	return buf + string(emoji[rem.Uint64()])
}

func decodeEmojiAddress(emojiAddr string) ([addrBytesLen]byte, error) {
	var result [addrBytesLen]byte
	if len([]rune(emojiAddr)) != emojiLen {
		return result, errors.New("could not decode emoji address: invalid length: " + emojiAddr)
	}
	num, err := fromBase(emojiAddr)
	if err != nil {
		return result, err
	}
	slice := num.FillBytes(make([]byte, addrBytesLen))
	copy(result[:], slice)
	return result, nil
}

func fromBase(enc string) (*big.Int, error) {
	result := new(big.Int)
	setlen := len(emoji)
	encRune := []rune(enc)
	numOfDigits := len(encRune)
	for i := 0; i < numOfDigits; i++ {
		mult := new(big.Int).Exp( // setlen ^ numOfDigits-i-1 = the "place value"
			big.NewInt(int64(setlen)),
			big.NewInt(int64(numOfDigits-i-1)),
			nil,
		)
		idx := findRuneIndex(encRune[i], emoji)
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
