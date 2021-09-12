package util

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"strings"
	// color library
)

// A Block represents a validated set of transactions with proof of work, which makes it really hard to rewrite the blockchain.
type Block struct {
	// Index is the Block number
	Index int64
	// Timestamp is the Unix timestamp in milliseconds of the date of creation of this Block
	Timestamp int64
	// Data stores any (arbitrary) additional data >= 250 kb long.
	Data string
	//Hash stores the hex value of the sha256 sum of the block represented as JSON with the indent as "   " and Hash as ""
	Hash string
	// PrevHash is the hash of the previous Block in the Blockchain
	PrevHash string
	// Solution is the nonce value that makes the Hash have a prefix of Difficulty zeros
	Solution string
	// Solver is the public key of the sender
	Solver string
	// Transaction is the transaction associated with this block
	Tx Transaction `json:",omitempty"`
}

// A Transaction is a transfer of any amount of duckcoin from one address to another.
type Transaction struct {
	// Data is any (arbitrary) additional data >= 250 kb long.
	Data string `json:",omitempty"`
	//Sender is the address of the sender.
	Sender string `json:",omitempty"`
	//Receiver is the address of the receiver.
	Receiver string `json:",omitempty"`
	//Amount is the amount to be payed by the Sender to the Receiver. It is always a positive number.
	Amount int64 `json:",omitempty"`
	//PubKey is the Duckcoin formatted public key of the sender
	PubKey    string `json:",omitempty"`
	Signature string `json:",omitempty"`
}

// CalculateHash calculates the hash of a Block.
func CalculateHash(block Block) string {
	block.Hash = ""
	block.Tx.Signature = ""
	return Shasum([]byte(ToJSON(block)))
}

// MakeSignature signs a message with a private key.
func MakeSignature(privkey string, message string) (string, error) {
	hash := sha256.Sum256([]byte(message))
	key, err := DuckToPrivateKey(privkey)
	if err != nil {
		return "", err
	}
	data, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return "", err
	}
	return B64(data), nil
}

// Shasum returns the sha256 hash of a byte slice
func Shasum(record []byte) string {
	h := sha256.New()
	h.Write(record)
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

// IsHashSolution checks if a hash is a valid block hash using the global Difficulty
func IsHashSolution(hash string, difficulty int) bool {
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}

// ToJSON is a convenience method for serializing to JSON
func ToJSON(v interface{}) string {
	s, _ := json.MarshalIndent(v, "", "   ")
	return string(s)
}

// ArgsHaveOption checks command line arguments for an option
func ArgsHaveOption(long string, short string) (hasOption bool, foundAt int) {
	for i, arg := range os.Args {
		if arg == "--"+long || arg == "-"+short {
			return true, i
		}
	}
	return false, 0
}

// PrivateKeytoDuck serializes private keys to a base64 string
func PrivateKeytoDuck(privkey *ecdsa.PrivateKey) (string, error) {
	marshalled, err := x509.MarshalECPrivateKey(privkey)
	if err != nil {
		return "", err
	}
	return B64(marshalled), nil
}

// DuckToPrivateKey deserializes private keys
func DuckToPrivateKey(duckkey string) (*ecdsa.PrivateKey, error) {
	d, err := base64.StdEncoding.DecodeString(duckkey)
	if err != nil {
		return nil, err
	}
	p, err := x509.ParseECPrivateKey(d)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// PublicKeytoDuck serializes public keys to a base64 string
func PublicKeytoDuck(pubkey *ecdsa.PublicKey) (string, error) {
	marshalled, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	return B64(marshalled), nil
}

// DuckToPublicKey deserializes public keys
func DuckToPublicKey(duckkey string) (*ecdsa.PublicKey, error) {
	d, err := base64.StdEncoding.DecodeString(duckkey)
	if err != nil {
		return nil, err
	}
	p, err := x509.ParsePKIXPublicKey(d)
	if err != nil {
		return nil, err
	}
	pubkey, ok := p.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("pubkey is not of type *ecdsa.PublicKey")
	}
	return pubkey, nil
}

// B64 encodes a byte array to a base64 string
func B64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DuckToAddress converts a Duckcoin public key to a Duckcoin address.
func DuckToAddress(duckkey string) string {
	hash := sha256.Sum256([]byte(duckkey))
	return B64(hash[:])
}

// CheckSignature checks if signature decodes to message using pubkey. This is useful in verifying identities.
func CheckSignature(signature string, pubkey string, message string) (bool, error) {
	decodedSig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256([]byte(message))
	key, err := DuckToPublicKey(pubkey)
	if err != nil {
		return false, err
	}
	return ecdsa.VerifyASN1(key, hash[:], decodedSig), nil
}

// SaveKeyPair saves a key pair to a file using the PEM format
func SaveKeyPair(pubkey string, privkey string, pubfile string, privfile string) error {
	// saveKeyPair decodes the keys because PEM base64s them too, and decoding means that the pubkey in duck format is the same as the data in the PEM file. (which is nice but an arbitrary decision)
	d, _ := base64.StdEncoding.DecodeString(privkey)
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "DUCKCOIN (ECDSA) PRIVATE KEY",
		Bytes: d,
	})
	if err := ioutil.WriteFile(privfile, b, 0600); err != nil {
		return err
	}

	d, _ = base64.StdEncoding.DecodeString(pubkey)
	b = pem.EncodeToMemory(&pem.Block{
		Type:  "DUCKCOIN (ECDSA) PUBLIC KEY",
		Bytes: d,
	})
	if err := ioutil.WriteFile(pubfile, b, 0644); err != nil {
		return err
	}

	return nil
}

func IsValidBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}
