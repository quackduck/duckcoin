package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

const (
	Difficulty      = 5
	BlockchainFile  = "blockchain.json"
	NewestBlockFile = "newestblock.json"
	BalancesFile    = "balances.json"
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
	// Sender is the public key of the sender.
	Sender string
	// Receiver is the public key of the receiver.
	Receiver string
	// Amount is the amount to be payed by the Sender to the Receiver. It is always a positive number or zero.
	Amount    int
	Signature string
}

var (
	// Blockchain is a series of Blocks
	//Blockchain []Block
	NewestBlock Block
	Balances    = make(map[string]int)
)

//// Message takes incoming JSON payload for writing heart rate
//type Message struct {
//	BPM int
//}

func main() {
	//go func() {
	if !fileExists(BlockchainFile) {
		t := time.Now() // genesis time
		genesisBlock := Block{0, t.Unix(), "Genesis block. Thank you so much to Jason Antwi-Appah for the incredible name that is Duckcoin. QUACK!", "", "🐤", "Go Gophers and DUCKS! github.com/quackduck", "Ishan Goel (quackduck on GitHub)", Transaction{"Genesis transaction", "", "", 0, ""}}
		genesisBlock.Hash = calculateHash(genesisBlock)
		fmt.Println(toJson(genesisBlock))
		f, _ := os.Create(BlockchainFile)
		f.Write([]byte(toJson([]Block{genesisBlock})))
		f.Close()
		NewestBlock = genesisBlock
		err := ioutil.WriteFile(NewestBlockFile, []byte(toJson(NewestBlock)), 0755)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = ioutil.WriteFile(BalancesFile, []byte(toJson(Balances)), 0755)
		if err != nil {
			fmt.Println(err)
			return
		}
	} else {
		b, err := ioutil.ReadFile(NewestBlockFile)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = json.Unmarshal(b, &NewestBlock)
		if err != nil {
			fmt.Println(err)
			return
		}
		b, err = ioutil.ReadFile(BalancesFile)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = json.Unmarshal(b, &Balances)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	mux := mux.NewRouter()
	mux.HandleFunc("/blocks", handleGetBlocks).Methods("GET")
	mux.HandleFunc("/balances", handleGetBalances).Methods("GET")
	mux.HandleFunc("/blocks/new", handleWriteBlock).Methods("POST")
	mux.HandleFunc("/blocks/newest", handleGetNewest).Methods("GET")

	mux.HandleFunc("/difficulty", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strconv.Itoa(Difficulty)))
	}).Methods("GET")

	go func() {
		s := &http.Server{
			Addr:           "0.0.0.0:80",
			Handler:        mux,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
		}
		if err := s.ListenAndServe(); err != nil {
			fmt.Println(err)
			return
		}
	}()
	httpPort := "8080"

	fmt.Println("HTTP Server Listening on port:", httpPort)
	s := &http.Server{
		Addr:           "0.0.0.0:" + httpPort,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	if err := s.ListenAndServe(); err != nil {
		fmt.Println(err)
		return
	}

}

type ECDSASignature struct {
	R, S *big.Int
}

//func makeKeyPair() (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
//	pubkeyCurve := elliptic.P256() // see http://golang.org/pkg/crypto/elliptic/#P256
//
//	privatekey, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader) // this generates a public & private key pair
//
//	if err != nil {
//		return nil, nil, err
//	}
//	pubkey := &privatekey.PublicKey
//	fmt.Println("Private Key:")
//	marshalled, _ := x509.MarshalPKCS8PrivateKey(privatekey)
//	fmt.Println(b64(marshalled))
//
//	fmt.Println("Public Key:")
//	marshalled, _ = x509.MarshalPKIXPublicKey(pubkey)
//	fmt.Println(b64(marshalled))
//	return pubkey, privatekey, nil
//}
//
//func saveKeyPair(pubkey *ecdsa.PublicKey, privkey *ecdsa.PrivateKey, pubfile string, privfile string) error {
//	marshalled, _ := x509.MarshalPKCS8PrivateKey(privkey)
//	b := pem.EncodeToMemory(&pem.Block{
//		Type:  "ECDSA PRIVATE KEY",
//		Bytes: marshalled,
//	})
//	if err := ioutil.WriteFile(privfile, b, 0755); err != nil {
//		return err
//	}
//
//	marshalled, _ = x509.MarshalPKIXPublicKey(pubkey)
//	b = pem.EncodeToMemory(&pem.Block{
//		Type:  "ECDSA PUBLIC KEY",
//		Bytes: marshalled,
//	})
//	if err := ioutil.WriteFile(pubfile, b, 0755); err != nil {
//		return err
//	}
//	return nil
//}
//
//func makeSignature(privatekey *ecdsa.PrivateKey, message string) (string, error) {
//	hash := sha256.Sum256([]byte(message))
//	r, s, err := ecdsa.Sign(rand.Reader, privatekey, hash[:])
//	if err != nil {
//		return "", err
//	}
//	signature, err := asn1.Marshal(ECDSASignature{r, s})
//	if err != nil {
//		return "", err
//	}
//	//signature := r.Bytes()
//	//signature = append(signature, s.Bytes()...)
//	fmt.Printf("Signature:" + b64(signature))
//	return b64(signature), nil
//}
//func b64(data []byte) string {
//	return base64.StdEncoding.EncodeToString(data)
//}

func checkSignature(signature string, pubkey *ecdsa.PublicKey, message string) (bool, error) {
	decodedSig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256([]byte(message))
	sig := new(ECDSASignature)
	err = gob.NewDecoder(bytes.NewReader(decodedSig)).Decode(&sig)
	if err != nil {
		return false, err
	}
	//_, err = asn1.Unmarshal(decodedSig, &sig)
	//if err != nil {
	//	fmt.Println("asn unmarshal error", err)
	//	return false, err
	//}
	//fmt.Println("verify got", ecdsa.Verify(pubkey, hash[:], sig.R, sig.S))
	return ecdsa.Verify(pubkey, hash[:], sig.R, sig.S), nil
}

func addBlockToChain(b Block) {
	Balances[b.Solver] += 1
	NewestBlock = b
	if b.Tx.Amount != 0 {
		Balances[b.Solver] -= b.Tx.Amount
		Balances[b.Tx.Receiver] += b.Tx.Amount
	}

	err := truncateFile(BlockchainFile, 2) // remove the last two parts (the bracket and the newline)
	if err != nil {
		fmt.Println("Could not truncate", BlockchainFile)
		return
	}
	f, err := os.OpenFile(BlockchainFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		fmt.Println("Could not open", BlockchainFile)
		return
	}
	bytes, err := json.MarshalIndent(b, "   ", "   ")
	if err != nil {
		fmt.Println("Could not marshal block to JSON")
		return
	}
	_, err = f.Write(append(append([]byte(",\n   "), bytes...), "\n]"...))
	if err != nil {
		fmt.Println("Could not write to", BlockchainFile)
	}
	f.Close()

	err = ioutil.WriteFile(NewestBlockFile, []byte(toJson(b)), 0755)
	if err != nil {
		fmt.Println("Could not write to", NewestBlockFile)
	}
	err = ioutil.WriteFile(BalancesFile, []byte(toJson(Balances)), 0755)
	if err != nil {
		fmt.Println("Could not write to", BalancesFile)
	}
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func truncateFile(name string, bytesToRemove int64) error {
	fi, err := os.Stat(name)
	if err != nil {
		return err
	}
	if fi.Size() < bytesToRemove {
		return nil
	}
	return os.Truncate(name, fi.Size()-bytesToRemove)
}

// create handlers
//func makeMuxRouter() http.Handler {
//
//
//	return muxRouter
//}

//func makeHandlerReturningJsonVal(v) func(w http.ResponseWriter, r *http.Request) {
//	return func(w http.ResponseWriter, r *http.Request) {
//		bytes, err := json.MarshalIndent(v, "", "  ")
//		if err != nil {
//			http.Error(w, err.Error(), http.StatusInternalServerError)
//			return
//		}
//		w.Write(bytes)
//	}
//}

func handleGetBlocks(w http.ResponseWriter, r *http.Request) {
	//bytes, err := json.MarshalIndent(Blockchain, "", "  ")
	//if err != nil {
	//	http.Error(w, err.Error(), http.StatusInternalServerError)
	//	return
	//}
	f, err := os.Open(BlockchainFile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.Copy(w, f)
	f.Close()
	//w.Write(bytes)
}
func handleGetBalances(w http.ResponseWriter, r *http.Request) {
	bytes, err := json.MarshalIndent(Balances, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(bytes)
}
func handleGetNewest(w http.ResponseWriter, r *http.Request) {
	bytes, err := json.MarshalIndent(NewestBlock, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(bytes)
}
func handleWriteBlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var b Block

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&b); err != nil {
		fmt.Println("Bad request")
		respondWithJSON(w, http.StatusBadRequest, r.Body)
		return
	}
	fmt.Println(b)
	defer r.Body.Close()

	if err := isValid(b, NewestBlock); err == nil {
		addBlockToChain(b)
	} else {
		respondWithJSON(w, http.StatusBadRequest, "Invalid block. "+err.Error())
		fmt.Println("Rejected block")
		return
	}
	respondWithJSON(w, http.StatusCreated, b)
}
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	response, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP 500: Internal Server Error: " + err.Error()))
		return
	}
	w.WriteHeader(code)
	w.Write(response)
}

func isValid(newBlock, oldBlock Block) error {
	if newBlock.Tx.Amount < 0 {
		return errors.New("Amount is negative")
	}
	if oldBlock.Index+1 != newBlock.Index {
		return errors.New("Index should be " + strconv.FormatInt(oldBlock.Index+1, 10))
	}
	if oldBlock.Hash != newBlock.PrevHash {
		return errors.New("PrevHash should be " + oldBlock.Hash)
	}
	if calculateHash(newBlock) != newBlock.Hash {
		return errors.New("Block Hash is incorrect")
	}
	if !isBlockSolution(newBlock.Hash) {
		return errors.New("Block is not a solution (does not have Difficulty zeros in hash)")
	}
	if newBlock.Tx.Amount > 0 {
		b, err := base64.StdEncoding.DecodeString(newBlock.Tx.Sender)
		if err != nil {
			return errors.New("Sender is not a base64 string")
		}
		pubkey, err := x509.ParsePKIXPublicKey(b)
		if err != nil {
			return errors.New("Public key cannot be parsed")
		}
		key, ok := pubkey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("Public key is not of type *ecdsa.PublicKey")
		}
		if ok, _ = checkSignature(newBlock.Tx.Signature, key, newBlock.Hash); !ok {
			return errors.New("Signature is not valid")
		}
		if newBlock.Tx.Sender == newBlock.Solver {
			if Balances[newBlock.Tx.Sender]+1 < newBlock.Tx.Amount { // plus 1 because that's the reward
				return errors.New("Insufficient balance")
			}
		} else {
			if Balances[newBlock.Tx.Sender] < newBlock.Tx.Amount {
				return errors.New("Insufficient balance")
			}
		}
	}
	//checkSignature(newBlock.Tx.Signature)
	return nil
}

func calculateHash(block Block) string {
	block.Hash = ""
	block.Tx.Signature = ""
	return shasum([]byte(toJson(block)))
	//return shasum([]byte(strconv.FormatInt(block.Index, 10) + strconv.FormatInt(block.Timestamp, 10) + block.Data + block.PrevHash + block.Solution + block.Solver))
}

func shasum(record []byte) string {
	h := sha256.New()
	h.Write(record)
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func isBlockSolution(hash string) bool {
	//hash := shasum([]byte(solution))
	prefix := strings.Repeat("0", Difficulty)
	return strings.HasPrefix(hash, prefix)
}

func toJson(v interface{}) string {
	s, _ := json.MarshalIndent(v, "", "   ")
	return string(s)
}
