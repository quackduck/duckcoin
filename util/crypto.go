package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"
)

const (
	// MicroquacksPerDuck is the number of microquacks equal to one duck.
	// A microquack is a billionth of a quack, which is a hundredth of a duck.
	MicroquacksPerDuck uint64 = 1e8
)

type Lblock struct {
	// Index is the Lblock number
	Index uint64
	// Timestamp is the Unix timestamp in milliseconds of the date of creation of this Lblock
	Timestamp uint64
	// Data stores any (arbitrary) additional data <= 250 kb long.
	Data string
	// Hash stores the hash of this Lblock as computed by CalculateHash
	Hash string
	// PrevHash is the hash of the previous Lblock
	PrevHash string
	// Solution is the nonce value that makes the Hash be under some target value
	Solution uint64
	// Solver is the address of the sender. Address format: Q + version char + base64(shasum(pubkey)[:20])
	Solver Address `json:",omitempty"`
	// Sblocks contains the Sblocks part of this Lblock
	Sblocks []*Sblock
}

// An Sblock is one block in the chain of some Lnode. It optionally contains a transaction and arbitrary data.
type Sblock struct {
	// Index is the Sblock number
	Index uint64
	// Timestamp is the Unix timestamp in milliseconds of the date of creation of this Sblock
	Timestamp uint64
	// Data stores any (arbitrary) additional data <= 250 kb long.
	Data string
	// Hash stores the hash of this Sblock as computed by CalculateHash
	Hash string
	// PrevHash is the hash of the previous Sblock
	PrevHash string
	// Solution is the nonce value that makes the Hash be under some target value
	Solution uint64
	// Solver is the address of the sender. Address format: Q + version char + base64(shasum(pubkey)[:20])
	Solver Address     `json:",omitempty"`
	Tx     Transaction `json:",omitempty"`
}

// A Transaction is a transfer of any amount of duckcoin from one address to another.
type Transaction struct {
	// Data is any (arbitrary) additional data <= 250 kb long.
	Data string `json:",omitempty"`
	// Sender is the address of the sender.
	Sender Address `json:",omitempty"`
	// Receiver is the address of the receiver.
	Receiver Address `json:",omitempty"`
	// Amount is the amount to be payed by the Sender to the Receiver. It is always a positive number.
	Amount uint64 `json:",omitempty"`
	// PubKey is the Duckcoin formatted public key of the sender
	PubKey string `json:",omitempty"`
	// Signature is a base64 encoded cryptographic signature that uses the hash of the Sblock
	// as the data encrypted by the private key to prevent replay attacks
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

// CalculateHash calculates the hash of a Sblock.
func (b *Sblock) CalculateHash() string {
	return hex.EncodeToString(b.CalculateHashBytes())
}

// CalculateHashBytes calculates the hash of a Sblock.
func (b *Sblock) CalculateHashBytes() []byte {
	return DoubleShasumBytes(b.Preimage())
}

// PreimageWOSolution returns the data to be hashed to create the hash of an Sblock, but without the Solution field taken into account.
// This is useful when mining.
func (b *Sblock) PreimageWOSolution() []byte {
	// lenCtrl hashes the bytes that a represents
	lenCtrl := func(a string) string { return string(DoubleShasumBytes([]byte(a))) }
	// all data fields are length-controlled so that the preimage always has around the same size (amount + timestamp + solution sizes can change, but not much)
	return []byte(strconv.FormatUint(b.Index, 10) + strconv.FormatUint(b.Timestamp, 10) + lenCtrl(b.Data) + b.PrevHash + string(b.Solver.bytes[:]) + // b.Hash is left out cause that's what's set later as the result of this func
		lenCtrl(b.Tx.Data) + string(b.Tx.Sender.bytes[:]) + string(b.Tx.Receiver.bytes[:]) + strconv.FormatUint(b.Tx.Amount, 10), // notice b.Tx.Signature is left out, that's also set later depending on this function's result
	)
}

func (b *Sblock) Preimage() []byte {
	return append(b.PreimageWOSolution(), strconv.FormatUint(b.Solution, 10)...)
}

// CalculateHash calculates the hash of an Lblock.
func (b *Lblock) CalculateHash() string {
	return hex.EncodeToString(b.CalculateHashBytes())
}

// CalculateHashBytes calculates the hash of an Lblock.
func (b *Lblock) CalculateHashBytes() []byte {
	return DoubleShasumBytes(b.Preimage())
}

func (b *Lblock) PreimageWOSolution() []byte {
	sblocksConcatenated := ""
	for i := range b.Sblocks {
		sblocksConcatenated += string(b.Sblocks[i].Preimage())
	}
	// lenCtrl hashes the bytes that a represents
	// see comments in PreimageWOSolution for why lenCtrl is used
	lenCtrl := func(a string) string { return string(DoubleShasumBytes([]byte(a))) }

	return []byte(strconv.FormatUint(b.Index, 10) + strconv.FormatUint(b.Timestamp, 10) + lenCtrl(b.Data) + b.PrevHash + string(b.Solver.bytes[:]) + // b.Hash is left out cause that's what's set later as the result of this func
		lenCtrl(sblocksConcatenated),
	)
}

func (b *Lblock) Preimage() []byte {
	return append(b.PreimageWOSolution(), strconv.FormatUint(b.Solution, 10)...)
}

// MakeSignature signs a message with a private key.
func MakeSignature(privkey, message string) (string, error) {
	hash := DoubleShasumBytes([]byte(message))
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

// DoubleShasumBytes returns sha256(sha256(record))
func DoubleShasumBytes(record []byte) []byte {
	h := sha256.New()
	h.Write(record)
	hashed := h.Sum(nil)
	h.Reset()
	h.Write(hashed)
	hashed = h.Sum(nil)
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
	return IsHashValidBytes(d.FillBytes(make([]byte, 32)), target)
}

// IsHashValidBytes checks if a hash is a valid block hash
func IsHashValidBytes(hash []byte, target *big.Int) bool {
	if len(hash) != 32 { // 32 bytes, a normal sha256 hash
		return false
	}
	d := new(big.Int).SetBytes(hash)
	return target.Cmp(d) == 1 // is target greater than d
}

// CheckSignature checks if signature decodes to message using pubkey. This is useful in verifying identities.
func CheckSignature(signature, pubkey, message string) (bool, error) {
	decodedSig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	hash := DoubleShasumBytes([]byte(message))
	key, err := duckToPublicKey(pubkey)
	if err != nil {
		return false, err
	}
	return ecdsa.VerifyASN1(key, hash, decodedSig), nil
}

// MakeKeyPair creates a new public and private key pair
func MakeKeyPair() (pub, priv string, err error) {
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
