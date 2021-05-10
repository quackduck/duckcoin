package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"
)

var (
	b           Block
	url         = "http://devzat.hackclub.com:8080"
	home, _     = os.UserHomeDir()
	u, _        = user.Current()
	username    = u.Name
	configDir   = home + "/.config/duckcoin"
	pubkeyFile  = configDir + "pubkey.pem"
	privkeyFile = configDir + "privkey.pem"
	Difficulty  = 5
)

type Block struct {
	// Index is the Block number in the Icoin Blockchain
	Index int64
	// Timestamp is the Unix timestamp of the date of creation of this Block
	Timestamp int64
	// Data stores any (arbitrary) additional data.
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

type Transaction struct {
	// Data is any (arbitrary) additional data.
	Data string
	//Sender is the public key of the sender.
	Sender string
	//Receiver is the public key of the receiver.
	Receiver string
	//Amount is the amount to be payed by the Sender to the Receiver. It is always a positive number.
	Amount    int
	Signature string
}

func main() {
	os.MkdirAll(configDir, 0755)
	solver, privkey, err := loadKeyPair(pubkeyFile, privkeyFile)
	if err != nil {
		fmt.Println(err)
		solver, privkey, err = makeKeyPair()
		if err != nil {
			fmt.Println(err)
			return
		}
		err = saveKeyPair(solver, privkey, pubkeyFile, privkeyFile)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	s, _ := x509.MarshalPKIXPublicKey(solver)
	solverEncoded := b64(s)
	s, _ = x509.MarshalPKCS8PrivateKey(privkey)
	privkeyEncoded := b64(s)
	fmt.Printf("Using these key pairs: \nPub: %s\nPriv:%s\n", solverEncoded, privkeyEncoded)
	if err != nil {
		fmt.Println(err)
		return
	}
	for {
		r, err := http.Get(url + "/blocks/newest")
		if err != nil {
			fmt.Println(err)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		_ = r.Body.Close()
		b = makeBlock(privkey, b, "Mined by the official Duckcoin CLI User: "+username, solverEncoded, Transaction{"", solverEncoded, "", 0, ""})
		j, jerr := json.Marshal(b)
		if jerr != nil {
			fmt.Println(err)
			return
		}
		r, err = http.Post(url+"/blocks/new", "application/json", bytes.NewBuffer(j))
		if err != nil {
			fmt.Println(err)
			return
		}
		resp, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(string(resp))
	}
}

// create a new block using previous block's hash
func makeBlock(privkey *ecdsa.PrivateKey, oldBlock Block, data string, solver string, tx Transaction) Block {
	var newBlock Block

	t := time.Now()

	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.Unix()
	newBlock.Data = data
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Solver = solver
	newBlock.Tx = tx

	for i := 0; ; i++ {
		newBlock.Solution = strconv.Itoa(i)
		if !isHashSolution(calculateHash(newBlock)) {
			// fmt.Println(calculateHash(newBlock))
			//fmt.Println(calculateHash(newBlock))
			//time.Sleep(time.Second)
			continue
		} else {
			newBlock.Hash = calculateHash(newBlock)
			signature, err := makeSignature(privkey, newBlock.Hash)
			if err != nil {
				fmt.Println(err)
				return Block{}
			}
			newBlock.Tx.Signature = signature
			fmt.Println(toJson(newBlock))
			break
		}
	}
	return newBlock
}

type ECDSASignature struct {
	R, S *big.Int
}

func b64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

//func keyEncode(v interface{}) string {
//	marshalled, _ := x509.MarshalPKCS8PrivateKey(v)
//	return b64(marshalled)
//}

func makeKeyPair() (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	pubkeyCurve := elliptic.P256() // see http://golang.org/pkg/crypto/elliptic/#P256

	privatekey, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader) // this generates a public & private key pair

	if err != nil {
		return nil, nil, err
	}
	pubkey := &privatekey.PublicKey
	//fmt.Println("Private Key:")
	//marshalled, _ := x509.MarshalPKCS8PrivateKey(privatekey)
	//fmt.Println(b64(marshalled))

	//fmt.Println("Public Key:")
	//marshalled, _ = x509.MarshalPKIXPublicKey(pubkey)
	//fmt.Println(b64(marshalled))
	return pubkey, privatekey, nil
}

func saveKeyPair(pubkey *ecdsa.PublicKey, privkey *ecdsa.PrivateKey, pubfile string, privfile string) error {
	marshalled, _ := x509.MarshalPKCS8PrivateKey(privkey)
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: marshalled,
	})
	if err := ioutil.WriteFile(privfile, b, 0755); err != nil {
		return err
	}

	marshalled, _ = x509.MarshalPKIXPublicKey(pubkey)
	b = pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PUBLIC KEY",
		Bytes: marshalled,
	})
	if err := ioutil.WriteFile(pubfile, b, 0755); err != nil {
		return err
	}
	return nil
}

func loadKeyPair(pubfile string, privfile string) (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(pubfile)
	if err != nil {
		return nil, nil, err
	}
	pukey, _ := pem.Decode(data)
	if pukey == nil {
		return nil, nil, errors.New("could not decode PEM data from " + pubfile)
	}
	p, err := x509.ParsePKIXPublicKey(pukey.Bytes)
	pubkey, ok := p.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("pubkey is not of type *ecdsa.PublicKey")
	}
	data, err = ioutil.ReadFile(privfile)
	if err != nil {
		return nil, nil, err
	}
	pukey, _ = pem.Decode(data)
	if pukey == nil {
		return nil, nil, errors.New("could not decode PEM data from " + privfile)
	}
	p, err = x509.ParsePKCS8PrivateKey(pukey.Bytes)
	privkey, ok := p.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("pubkey is not of type *ecdsa.PrivateKey")
	}
	return pubkey, privkey, nil
}

func makeSignature(privatekey *ecdsa.PrivateKey, message string) (string, error) {
	hash := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, privatekey, hash[:])
	if err != nil {
		return "", err
	}
	b := new(bytes.Buffer)
	err = gob.NewEncoder(b).Encode(ECDSASignature{r, s})
	if err != nil {
		return "", err
	}
	//signature, err := asn1.Marshal(ECDSASignature{r, s})
	//if err != nil {
	//	return "", err
	//}
	//signature := r.Bytes()
	//signature = append(signature, s.Bytes()...)
	fmt.Printf("Signature:" + b64(b.Bytes()))
	fmt.Printf("hash %v key %x", hash, privatekey.PublicKey)
	return b64(b.Bytes()), nil
}

func calculateHash(block Block) string {
	block.Hash = ""
	block.Tx.Signature = ""
	return shasum([]byte(toJson(block)))
}

func shasum(record []byte) string {
	h := sha256.New()
	h.Write(record)
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func isHashSolution(hash string) bool {
	prefix := strings.Repeat("0", Difficulty)
	return strings.HasPrefix(hash, prefix)
}

func toJson(v interface{}) string {
	s, _ := json.MarshalIndent(v, "", "   ")
	return string(s)
}
