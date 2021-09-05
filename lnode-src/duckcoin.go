package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

const (
	Difficulty       = 5
	BlockchainFile   = "blockchain.json"
	NewestBlockFile  = "newestblock.json"
	BalancesFile     = "balances.json"
	duckToMicroquacks = 1e8
	reward           = 1e6
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

var (
	NewestBlock Block
	Balances    = make(map[string]int)
)

func main() {
	if !fileExists(BlockchainFile) {
		t := time.Now() // genesis time
		genesisBlock := Block{0, t.Unix(), "Genesis block. Thank you so much to Jason Antwi-Appah for the incredible name that is Duckcoin. QUACK!", "", "🐤", "Go Gophers and DUCKS! github.com/quackduck", "Ishan Goel (quackduck on GitHub)", Transaction{"Genesis transaction", "", "", 0, "", ""}}
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

func checkSignature(signature string, pubkey string, message string) (bool, error) {
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

func addBlockToChain(b Block) {
	Balances[b.Solver] += reward
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

func handleGetBlocks(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(BlockchainFile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.Copy(w, f)
	f.Close()
}

func handleGetBalances(w http.ResponseWriter, r *http.Request) {
	balancesNew := make(map[string]float64)

	for address, balance := range Balances {
		balancesNew[address] = float64(balance) / float64(duckToMicroquacks)
	}

	bytes, err := json.MarshalIndent(balancesNew, "", "  ")
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

	decoder := json.NewDecoder(io.LimitReader(r.Body, 1e6))
	if err := decoder.Decode(&b); err != nil {
		fmt.Println("Bad request. This may be caused by a block that is too big (more than 1mb) but these are usually with malicious intent.")
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
	respondWithJSON(w, http.StatusCreated, "Block accepted.")
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
	const blockDataLimit = 1e3 * 250
	const txDataLimit = 1e3 * 250

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
		return errors.New("Block Hash is incorrect. This usually happens if your Difficulty is set incorrectly. Restart your miner.")
	}
	if !isBlockSolution(newBlock.Hash) {
		return errors.New("Block is not a solution (does not have Difficulty zeros in hash)")
	}
	if len(newBlock.Data) > blockDataLimit {
		return errors.New("Block's Data field is too large. Should be <= 250 kb")
	}
	if len(newBlock.Tx.Data) > txDataLimit {
		return errors.New("Transaction's Data field is too large. Should be <= 250 kb")
	}
	if newBlock.Tx.Amount > 0 {
		if duckToAddress(newBlock.Tx.PubKey) != newBlock.Tx.Sender {
			return errors.New("Pubkey does not match sender address")
		}
		if ok, err := checkSignature(newBlock.Tx.Signature, newBlock.Tx.PubKey, newBlock.Hash); !ok {
			if err != nil {
				return err
			} else {
				return errors.New("Invalid signature")
			}
		}
		if newBlock.Tx.Sender == newBlock.Solver {
			if Balances[newBlock.Tx.Sender] + reward < newBlock.Tx.Amount { 
				return errors.New("Insufficient balance")
			}
		} else {
			if Balances[newBlock.Tx.Sender] < newBlock.Tx.Amount {
				return errors.New("Insufficient balance")
			}
		}
	}
	return nil
}

func duckToAddress(duckkey string) string {
	hash := sha256.Sum256([]byte(duckkey))
	return base64.StdEncoding.EncodeToString(hash[:])
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

func isBlockSolution(hash string) bool {
	prefix := strings.Repeat("0", Difficulty)
	return strings.HasPrefix(hash, prefix)
}

func toJson(v interface{}) string {
	s, _ := json.MarshalIndent(v, "", "   ")
	return string(s)
}

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
