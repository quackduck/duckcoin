package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
)

const (
	// MicroquacksPerDuck is the number of microquacks equal to one duck.
	// A microquack is a billionth of a quack, which is a hundredth of a duck.
	MicroquacksPerDuck uint64 = 1e8
)

// A Block represents data optionally with a transaction including proof of work,
// which makes it really hard to rewrite the blockchain.
type Block struct {
	// Index is the Block number
	Index uint64
	// Timestamp is the Unix timestamp in milliseconds of the date of creation of this Block
	Timestamp uint64
	// Data stores any (arbitrary) additional data >= 250 kb long.
	Data string
	//Hash stores the hash as computed by CalculateHash
	Hash string
	// PrevHash is the hash of the previous Block in the Blockchain
	PrevHash string
	// Solution is the nonce value that makes the Hash have a prefix of Difficulty zeros
	Solution string
	// Solver is the address of the sender
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
	Amount uint64 `json:",omitempty"`
	//PubKey is the Duckcoin formatted public key of the sender
	PubKey    string `json:",omitempty"`
	Signature string `json:",omitempty"`
}

// GetTarget returns a "target" which block hashes must be lower than to be valid.
// This is calculated such that miners will need to compute difficulty hashes on average
// for a valid hash.
func GetTarget(difficulty uint64) *big.Int {
	d := new(big.Int)
	// this is the number of possible hashes: 16^64 = 2^256
	d.Lsh(big.NewInt(1), 256)
	// now divide by t so that there's a 1/t chance that a hash is smaller than Difficulty
	// this works because the total pool of valid hashes will become t times smaller than the max size
	d.Quo(d, big.NewInt(int64(difficulty)))
	return d
}

// CalculateHash calculates the hash of a Block.
func CalculateHash(block *Block) string {
	return hex.EncodeToString(CalculateHashBytes(block))
}

// CalculateHashBytes calculates the hash of a Block.
func CalculateHashBytes(b *Block) []byte {
	return ShasumBytes(
		[]byte(strconv.FormatInt(int64(b.Index), 10) + strconv.FormatInt(int64(b.Timestamp), 10) + b.Data + b.PrevHash + b.Solution + b.Solver + // b.Hash is left out cause that's what's set later as the result of this func
			b.Tx.Data + b.Tx.Sender + b.Tx.Receiver + strconv.FormatInt(int64(b.Tx.Amount), 10), // notice b.Tx.Signature is left out, that's also set later depending on this func's result
		),
	)
}

// MakeSignature signs a message with a private key.
func MakeSignature(privkey string, message string) (string, error) {
	hash := sha256.Sum256([]byte(message))
	key, err := duckToPrivateKey(privkey)
	if err != nil {
		return "", err
	}
	data, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// Shasum returns the sha256 hash of a byte slice
func Shasum(record []byte) string {
	return hex.EncodeToString(ShasumBytes(record))
}

// ShasumBytes returns the sha256 hash of a byte slice
func ShasumBytes(record []byte) []byte {
	h := sha256.New()
	h.Write(record)
	hashed := h.Sum(nil)
	return hashed
}

// IsHashValid checks if a hash is a valid block hash
func IsHashValid(hash string, target *big.Int) bool {
	if len(hash) != 64 { // 32 bytes == 64 hex chars
		return false
	}
	d, ok := new(big.Int).SetString(hash, 16)
	if !ok {
		return ok
	}
	return IsHashValidBytes(d.FillBytes(make([]byte, 32, 32)), target)
}

// IsHashValidBytes checks if a hash is a valid block hash
func IsHashValidBytes(hash []byte, target *big.Int) bool {
	if len(hash) != 32 { // 32 bytes, a normal sha256 hash
		return false
	}
	d := new(big.Int).SetBytes(hash)
	return target.Cmp(d) == 1 // is target greater than d
}

// ToJSON is a convenience method for serializing to JSON.
// Use ToJSONNice for output seen by humans.
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

// DuckToAddress converts a Duckcoin public key to a Duckcoin address.
func DuckToAddress(key string) string {
	hash := sha256.Sum256([]byte(key))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// CheckSignature checks if signature decodes to message using pubkey. This is useful in verifying identities.
func CheckSignature(signature string, pubkey string, message string) (bool, error) {
	decodedSig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256([]byte(message))
	key, err := duckToPublicKey(pubkey)
	if err != nil {
		return false, err
	}
	return ecdsa.VerifyASN1(key, hash[:], decodedSig), nil
}

// MakeKeyPair creates a new public and private key pair
func MakeKeyPair() (pub string, priv string, err error) {
	pubkeyCurve := elliptic.P256()                              // see http://golang.org/pkg/crypto/elliptic/#P256
	privkey, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader) // this generates a public & private key pair

	if err != nil {
		return "", "", err
	}
	pubkey := &privkey.PublicKey
	pub, err = publicKeytoDuck(pubkey)
	if err != nil {
		return "", "", err
	}
	priv, err = privateKeytoDuck(privkey)
	if err != nil {
		return "", "", err
	}
	return pub, priv, nil
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

// LoadKeyPair loads a key pair from pubfile and privfile
func LoadKeyPair(pubfile string, privfile string) (pub string, priv string, err error) {
	// see comment in util.SaveKeyPair for why the keys are base64 encoded before returning
	data, err := ioutil.ReadFile(pubfile)
	if err != nil {
		return "", "", err
	}
	key, _ := pem.Decode(data)
	if key == nil {
		return "", "", errors.New("could not decode PEM data from " + pubfile)
	}
	pubkey := base64.StdEncoding.EncodeToString(key.Bytes)
	data, err = ioutil.ReadFile(privfile)
	if err != nil {
		return "", "", err
	}
	key, _ = pem.Decode(data)
	if key == nil {
		return "", "", errors.New("could not decode PEM data from " + privfile)
	}
	privkey := base64.StdEncoding.EncodeToString(key.Bytes)
	return pubkey, privkey, nil
}

// IsValidBase64 checks if a string is valid base64
func IsValidBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// privateKeytoDuck serializes private keys to a base64 string
func privateKeytoDuck(privkey *ecdsa.PrivateKey) (string, error) {
	marshalled, err := x509.MarshalECPrivateKey(privkey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(marshalled), nil
}

// duckToPrivateKey deserializes private keys
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

// publicKeytoDuck serializes public keys to a base64 string
func publicKeytoDuck(pubkey *ecdsa.PublicKey) (string, error) {
	marshalled, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(marshalled), nil
}

// duckToPublicKey deserializes public keys
func duckToPublicKey(duckkey string) (*ecdsa.PublicKey, error) {
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
