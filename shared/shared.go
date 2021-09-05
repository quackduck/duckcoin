package shared

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
)

// CalculateHash calculates the hash of a Block.
func CalculateHash(block Block) string {
	block.Hash = ""
	block.Tx.Signature = ""
	return Shasum([]byte(ToJSON(block)))
}

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

func ToJSON(v interface{}) string {
	s, _ := json.MarshalIndent(v, "", "   ")
	return string(s)
}

func ArgsHaveOption(long string, short string) (hasOption bool, foundAt int) {
	for i, arg := range os.Args {
		if arg == "--"+long || arg == "-"+short {
			return true, i
		}
	}
	return false, 0
}

// duckToPrivateKey returns a deserialized base64 encoded private key
func duckToPrivateKey(duckkey string) (*ecdsa.PrivateKey, error) {
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

// publicKeytoduck returns a serialized public key as a base64 string
func publicKeytoduck(pubkey *ecdsa.PublicKey) (string, error) {
	marshalled, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	return b64(marshalled), nil
}

// b64 encodes a byte array to a base64 string
func b64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// privateKeytoduck returns a serialized private key as a base64 string
func privateKeytoduck(privkey *ecdsa.PrivateKey) (string, error) {
	marshalled, err := x509.MarshalECPrivateKey(privkey)
	if err != nil {
		return "", err
	}
	return b64(marshalled), nil
}

// duckToAddress converts a Duckcoin public key to a Duckcoin address.
func duckToAddress(duckkey string) string {
	hash := sha256.Sum256([]byte(duckkey))
	return b64(hash[:])
}

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
	Tx Transaction
}

// A Transaction is a transfer of any amount of duckcoin from one address to another.
type Transaction struct {
	// Data is any (arbitrary) additional data >= 250 kb long.
	Data string
	//Sender is the address of the sender.
	Sender string
	//Receiver is the address of the receiver.
	Receiver string
	//Amount is the amount to be payed by the Sender to the Receiver. It is always a positive number.
	Amount int
	//PubKey is the Duckcoin formatted public key of the sender
	PubKey    string
	Signature string
}
