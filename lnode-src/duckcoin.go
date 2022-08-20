package main

import (
	"encoding/json"
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
	DefaultPort = "4213" // D U C => 4 21 3

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

	util.DBInit() // opens duckchain.db in current working dir

	Past100Durations = append(Past100Durations, TargetDuration)
	Difficulty = 1048576 * 6 // EDITT!!!! TODO

	if err := setup(); err != nil {
		fmt.Println("error: ", err)
		return
	}

	m := mux.NewRouter()
	m.HandleFunc("/sblocks", handleGetSblocks).Methods("GET")
	m.HandleFunc("/balances", getHandleGetBalancesFunc(func(address util.Address) string {
		return address.Emoji
	})).Methods("GET")
	m.HandleFunc("/balances-text", getHandleGetBalancesFunc(func(address util.Address) string {
		return address.Text
	})).Methods("GET")
	m.HandleFunc("/sblocks/new", handleWriteSblock).Methods("POST")
	m.HandleFunc("/sblocks/newest", handleGetNewest).Methods("GET")

	m.HandleFunc("/lblocks/new", handleWriteLblock).Methods("POST")

	m.HandleFunc("/difficulty", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(strconv.FormatInt(int64(Difficulty), 10)))
		if err != nil {
			fmt.Println("error: ", err)
			return
		}
	}).Methods("GET")

	port := os.Getenv("PORT")
	if port == "" {
		port = DefaultPort
	}
	fmt.Println("HTTP Server Listening on port", port)
	s := &http.Server{
		Addr:           "0.0.0.0:" + port,
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

func getHandleGetBalancesFunc(addrToString func(address util.Address) string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		balances := util.GetAllBalancesFloats()
		balancesJSONMap := make(map[string]float64, len(balances))
		for addr, balance := range balances {
			balancesJSONMap[addrToString(addr)] = balance
		}
		bytes, err := json.MarshalIndent(balancesJSONMap, "", "  ")
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

	if err := util.IsValid(b, NewestBlock, util.GetTarget(Difficulty)); err == nil {
		addBlockToChain(b)
	} else {
		respondWithJSON(w, http.StatusBadRequest, "Invalid block. "+err.Error())
		fmt.Println("Rejected a block")
		return
	}

	go func() {
		err := sendToLnodes(&util.Lblock{ // just a test for now, no mining is happening
			Index:     23,
			Timestamp: b.Timestamp,
			Data:      "Yo bro, I just got a new block! " + b.Hash,
			Hash:      b.Hash,
			PrevHash:  b.PrevHash,
			Solution:  b.Solution,
			Solver:    b.Solver,
			Sblocks:   []*util.Sblock{b, b},
		})
		if err != nil {
			fmt.Println("error:", err)
		}
	}()
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

func reCalcDifficulty() {
	var avg uint64 = 0
	var i uint64 = 0
	for _, v := range Past100Durations {
		avg += uint64(v)
		i++
	}
	avg /= i
	avgDur := time.Duration(avg)
	fmt.Printf("The average duration between blocks for the past %d blocks was: %s\n", ReCalcInterval, avgDur.String())
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
	newArr := make([]string, 0, len(s))
	for i := range s {
		if strings.TrimSpace(s[i]) != "" {
			newArr = append(newArr, strings.TrimSpace(s[i]))
		}
	}
	return newArr, nil
}
