package main

import (
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
	"github.com/jwalton/gchalk"
	"github.com/quackduck/duckcoin/util"
)

var (
	NewestBlock *util.Sblock

	ReCalcInterval   = 100 // Recalculate difficulty every 100 sblocks
	Past100Durations = make([]time.Duration, 0, ReCalcInterval)
	NewestBlockTime  = time.Now()
	TargetDuration   = time.Second * 30

	// Difficulty is the number of hashes needed for an sblock to be valid on average.
	// See util.GetTarget for more information.
	Difficulty uint64

	Pubkey  string
	Privkey string
	Addr    util.Address

	PubkeyFile  = getConfigDir() + "/pubkey.pem"
	PrivkeyFile = getConfigDir() + "/privkey.pem"
	LnodesFile  = getConfigDir() + "/lnodes.txt"
	Lnodes      []string
)

func main() {
	var err error
	Pubkey, Privkey, Addr, err = util.LoadKeysAndAddr(PubkeyFile, PrivkeyFile)
	if err != nil {
		fmt.Println("Making you a fresh, new key pair and address!")
		Pubkey, Privkey, err = util.MakeKeyPair()
		if err != nil {
			fmt.Println("error", err)
			return
		}
		err = util.SaveKeyPair(Pubkey, Privkey, PubkeyFile, PrivkeyFile)
		if err != nil {
			fmt.Println("error", err)
			return
		}
		gchalk.BrightYellow("Your keys have been saved to " + PubkeyFile + "(pubkey) and " + PrivkeyFile + " (privkey)")
		gchalk.BrightRed("Do not tell anyone what's inside " + PrivkeyFile)
	}

	gchalk.BrightYellow("Loaded keys from " + PubkeyFile + " and " + PrivkeyFile)
	fmt.Println("Mining to this address:", gchalk.BrightBlue(Addr.Emoji))
	Lnodes, err = parseLnodesFile(LnodesFile)
	if err != nil {
		fmt.Println("error", err)
		return
	}

	util.DBInit()

	Past100Durations = append(Past100Durations, TargetDuration)
	Difficulty = 1048576 * 6 // EDITT!!!! TODO

	if err := setup(); err != nil {
		fmt.Println("error: ", err)
		return
	}

	m := mux.NewRouter()
	m.HandleFunc("/sblocks", handleGetSblocks).Methods("GET")
	m.HandleFunc("/balances", handleGetBalances).Methods("GET")
	m.HandleFunc("/sblocks/new", handleWriteSblock).Methods("POST")
	m.HandleFunc("/sblocks/newest", handleGetNewest).Methods("GET")

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
	NewestBlock, err = util.GetNewestSblock()
	if err != nil {
		return err
	}
	return nil
}

func addBlockToChain(b *util.Sblock) {
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

func handleGetSblocks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "keep-alive")

	var i uint64
	blockData := make([]byte, 0, 500*1024)
	for i = 0; i <= NewestBlock.Index; i++ {
		b, err := util.GetSblockByIndex(i)
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
	bytes, err := json.MarshalIndent(NewestBlock, "", "  ")
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

func handleWriteSblock(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	b := new(util.Sblock)

	decoder := json.NewDecoder(io.LimitReader(r.Body, 1e6))
	if err := decoder.Decode(b); err != nil {
		//fmt.Println("Bad JSON request. This may be caused by a block that is too big (more than 1mb) but these are usually with malicious intent. " + err.Error())
		respondWithJSON(w, http.StatusBadRequest, "Bad JSON request. This may be caused by a block that is too big (more than 1mb) but these are usually with malicious intent. "+err.Error())
		return
	}

	if err := isValid(b, NewestBlock); err == nil {
		addBlockToChain(b)
	} else {
		respondWithJSON(w, http.StatusBadRequest, "Invalid block. "+err.Error())
		fmt.Println("Rejected a block")
		return
	}
	respondWithJSON(w, http.StatusCreated, "Sblock accepted.")
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

func isValid(newBlock, oldBlock *util.Sblock) error {
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
		return errors.New("Sblock timestamp is not within 5 minutes before current time. What are you trying to pull off here?")
	}
	if err := util.IsAddressValid(newBlock.Solver); err != nil {
		return errors.New("Sender is invalid: " + err.Error())
	}
	if util.CalculateHash(newBlock) != newBlock.Hash {
		return errors.New("Sblock Hash does not match actual hash.")
	}
	if !util.IsHashValid(newBlock.Hash, util.GetTarget(Difficulty)) {
		return errors.New("Sblock is not a solution (does not have Difficulty zeros in hash)")
	}
	if len(newBlock.Data) > blockDataLimit {
		return errors.New("Sblock's Data field is too large. Should be >= 250 kb")
	}
	if len(newBlock.Tx.Data) > txDataLimit {
		return errors.New("Transaction's Data field is too large. Should be >= 250 kb")
	}
	if newBlock.Tx.Amount > 0 {
		if util.IsAddressValid(newBlock.Tx.Sender) != nil || util.IsAddressValid(newBlock.Tx.Receiver) != nil || !util.IsValidBase64(newBlock.Tx.PubKey) ||
			!util.IsValidBase64(newBlock.Tx.Signature) {
			return errors.New("At least one of the Sender, Receiver, PubKey or Signature is not valid. What are you trying to pull here?")
		}
		if util.KeyToAddress(newBlock.Tx.PubKey) != newBlock.Tx.Sender {
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

func getConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(0)
	}
	err = os.MkdirAll(home+"/.config/duckcoin", 0700)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	return home + "/.config/duckcoin"
}

func parseLnodesFile(f string) ([]string, error) {
	data, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	s := strings.Split(string(data), "\n")
	for i := range s {
		s[i] = strings.TrimSpace(s[i])
	}
	return s, nil
}
