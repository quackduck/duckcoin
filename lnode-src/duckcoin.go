package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/quackduck/duckcoin/util"
)

var (
	NewestBlock *util.Block

	ReCalcInterval   = 100
	Past100Durations = make([]time.Duration, 0, ReCalcInterval)
	NewestBlockTime  = time.Now()
	TargetDuration   = time.Second * 30

	// Difficulty is the number of hashes needed for a block to be valid on average.
	// See util.GetTarget for more information.
	Difficulty uint64
)

func main() {
	util.DBInit()

	Past100Durations = append(Past100Durations, TargetDuration)
	Difficulty = 1048576 * 6

	if err := setup(); err != nil {
		fmt.Println("error: ", err)
		return
	}

	m := mux.NewRouter()
	m.HandleFunc("/blocks", handleGetBlocks).Methods("GET")
	m.HandleFunc("/balances", handleGetBalances).Methods("GET")
	m.HandleFunc("/blocks/new", handleWriteBlock).Methods("POST")
	m.HandleFunc("/blocks/newest", handleGetNewest).Methods("GET")

	m.HandleFunc("/difficulty", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(strconv.FormatInt(int64(Difficulty), 10)))
		if err != nil {
			fmt.Println("error: ", err)
			return
		}
	}).Methods("GET")

	go func() {
		s := &http.Server{
			Addr:           "0.0.0.0:80",
			Handler:        m,
			ReadTimeout:    10 * time.Minute,
			WriteTimeout:   10 * time.Minute,
			MaxHeaderBytes: 1 << 20,
		}
		if err := s.ListenAndServe(); err != nil {
			fmt.Println(err)
			return
		}
	}()

	fmt.Println("HTTP Server Listening on port 8080")
	s := &http.Server{
		Addr:           "0.0.0.0:8080",
		Handler:        m,
		ReadTimeout:    10 * time.Minute,
		WriteTimeout:   10 * time.Minute,
		MaxHeaderBytes: 1 << 20,
	}
	if err := s.ListenAndServe(); err != nil {
		fmt.Println(err)
		return
	}
}

func setup() error {
	var err error
	NewestBlock, err = util.GetNewestBlock()
	if err != nil {
		return err
	}
	return nil
}

func addBlockToChain(b *util.Block) {
	fmt.Println("Adding a block with hash:", b.Hash+". This one came in", time.Since(NewestBlockTime), "after the previous block.")

	if len(Past100Durations) < ReCalcInterval {
		Past100Durations = append(Past100Durations, time.Since(NewestBlockTime))
	} else { // trigger a recalculation of the difficulty
		reCalcDifficulty()
		Past100Durations = make([]time.Duration, 0, ReCalcInterval)
	}
	util.WriteBlockDB(b)
	NewestBlockTime = time.Now()
	NewestBlock = b
}

func handleGetBlocks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "keep-alive")

	var i uint64
	blockData := make([]byte, 0, 500*1024)
	for i = 0; i <= NewestBlock.Index; i++ {
		b, err := util.GetBlockByIndex(int64(i))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		blockData = append(blockData, util.ToJSON(b)...)
		if i%1000 == 0 {
			w.Write(blockData)
			blockData = make([]byte, 0, 500*1024)
		}
	}
	w.Write(blockData)
}

func handleGetBalances(w http.ResponseWriter, _ *http.Request) {
	balancesNew := util.GetAllBalancesFloats()
	bytes, err := json.MarshalIndent(balancesNew, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = w.Write(bytes)
	if err != nil {
		fmt.Println("error: ", err)
		return
	}
}

func handleGetNewest(w http.ResponseWriter, _ *http.Request) {
	newestBlock, err := util.GetNewestBlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	bytes, err := json.MarshalIndent(newestBlock, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = w.Write(bytes)
	if err != nil {
		fmt.Println("error: ", err)
		return
	}
}

func handleWriteBlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	b := new(util.Block)

	decoder := json.NewDecoder(io.LimitReader(r.Body, 1e6))
	if err := decoder.Decode(b); err != nil {
		//fmt.Println("Bad JSON request. This may be caused by a block that is too big (more than 1mb) but these are usually with malicious intent. " + err.Error())
		respondWithJSON(w, http.StatusBadRequest, "Bad JSON request. This may be caused by a block that is too big (more than 1mb) but these are usually with malicious intent. "+err.Error())
		return
	}
	//fmt.Println(b)
	defer r.Body.Close()

	if err := isValid(b, NewestBlock); err == nil {
		addBlockToChain(b)
	} else {
		respondWithJSON(w, http.StatusBadRequest, "Invalid block. "+err.Error())
		fmt.Println("Rejected a block")
		return
	}
	respondWithJSON(w, http.StatusCreated, "Block accepted.")
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	response, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("HTTP 500: Internal Server Error: " + err.Error()))
		if err != nil {
			fmt.Println("error: ", err)
			return
		}
		return
	}
	w.WriteHeader(code)
	_, err = w.Write(response)
	if err != nil {
		fmt.Println("error: ", err)
		return
	}
}

func isValid(newBlock, oldBlock *util.Block) error {
	const blockDataLimit = 1e3 * 250
	const txDataLimit = 1e3 * 250

	if newBlock.Tx.Amount < 0 {
		return errors.New("Amount is negative")
	}
	if oldBlock.Index+1 != newBlock.Index {
		return errors.New("Index should be " + strconv.FormatInt(int64(oldBlock.Index+1), 10))
	}
	if oldBlock.Hash != newBlock.PrevHash {
		return errors.New("PrevHash should be " + oldBlock.Hash)
	}
	if uint64(time.Now().UnixMilli())-newBlock.Timestamp > 1e3*60*5 { // 5 minutes in millis
		return errors.New("Block timestamp is not within 5 minutes before current time. What are you trying to pull off here?")
	}

	if !util.IsValidBase64(newBlock.Solver) ||
		!util.IsValidBase64(newBlock.Tx.Sender) ||
		!util.IsValidBase64(newBlock.Tx.Receiver) ||
		!util.IsValidBase64(newBlock.Tx.PubKey) ||
		!util.IsValidBase64(newBlock.Tx.Signature) {
		return errors.New("One or more of the Solver, Sender, Receiver, PubKey or Signature is not valid base64. What are you trying to pull here?")
	}

	if util.CalculateHash(newBlock) != newBlock.Hash {
		return errors.New("Block Hash does not match actual hash.")
	}
	if !util.IsHashValid(newBlock.Hash, util.GetTarget(Difficulty)) {
		return errors.New("Block is not a solution (does not have Difficulty zeros in hash)")
	}
	if len(newBlock.Data) > blockDataLimit {
		return errors.New("Block's Data field is too large. Should be >= 250 kb")
	}
	if len(newBlock.Tx.Data) > txDataLimit {
		return errors.New("Transaction's Data field is too large. Should be >= 250 kb")
	}
	if newBlock.Tx.Amount > 0 {
		if util.DuckToAddress(newBlock.Tx.PubKey) != newBlock.Tx.Sender {
			return errors.New("Pubkey does not match sender address")
		}
		if ok, err := util.CheckSignature(newBlock.Tx.Signature, newBlock.Tx.PubKey, newBlock.Hash); !ok {
			if err != nil {
				return err
			} else {
				return errors.New("Invalid signature")
			}
		}
		senderBalance, err := util.GetBalanceByAddr(newBlock.Tx.Sender)
		if err != nil {
			return errors.New("Internal Server Error")
		}
		if senderBalance < newBlock.Tx.Amount { // notice that there is no reward for this block's PoW added to the sender's account first
			return errors.New(fmt.Sprintf("Insufficient balance %d microquacks (sender balance) is less than %d microquacks (tx amount)", senderBalance, newBlock.Tx.Amount))
		}
	}
	return nil
}

func reCalcDifficulty() {
	var avg uint64 = 0
	var i uint64 = 0
	for _, v := range Past100Durations {
		avg += uint64(v)
		i++
	}
	avg /= i
	avgDur := time.Duration(avg)
	fmt.Println(fmt.Sprintf("The average duration between blocks for the past %d blocks was: %s", ReCalcInterval, avgDur.String()))
	// TargetDuration/avgDur is the scale factor for what the current target is
	// if avgDur is higher than TargetDuration, then the Difficulty will be made lower
	// if avgDur is lower, then the Difficulty will be made higher
	Difficulty = (Difficulty * uint64(TargetDuration)) / avg
	fmt.Println("\nRecalculated difficulty. It is now", Difficulty)
}
