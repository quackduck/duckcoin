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
	"time"

	"github.com/gorilla/mux"
	"github.com/quackduck/duckcoin/util"
)

const (
	Difficulty        = 5 // this should change based on time taken by each block
	BlockchainFile    = "blockchain.json"
	NewestBlockFile   = "newestblock.json"
	BalancesFile      = "balances.json"
	duckToMicroquacks = 1e8
	reward            = 1e6
)

var (
	NewestBlock util.Block
	Balances    = make(map[string]int)
)

func main() {
	if !fileExists(BlockchainFile) {
		t := time.Now() // genesis time
		genesisBlock := util.Block{
			Index:     0,
			Timestamp: t.Unix(),
			Data:      "Genesis block. Thank you so much to Jason Antwi-Appah for the incredible name that is Duckcoin. QUACK!",
			Hash:      "",
			PrevHash:  "🐤",
			Solution:  "Go Gophers and DUCKS! github.com/quackduck",
			Solver:    "Ishan Goel (quackduck on GitHub)",
			Tx: util.Transaction{
				Data: "Genesis transaction",
			},
		}

		genesisBlock.Hash = util.CalculateHash(genesisBlock)
		fmt.Println(util.ToJSON(genesisBlock))
		f, _ := os.Create(BlockchainFile)
		f.Write([]byte(util.ToJSON([]util.Block{genesisBlock})))
		f.Close()
		NewestBlock = genesisBlock
		err := ioutil.WriteFile(NewestBlockFile, []byte(util.ToJSON(NewestBlock)), 0755)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = ioutil.WriteFile(BalancesFile, []byte(util.ToJSON(Balances)), 0755)
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