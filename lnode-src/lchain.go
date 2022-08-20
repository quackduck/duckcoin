package main

import (
	"encoding/json"
	"fmt"
	"github.com/quackduck/duckcoin/util"
	"io"
	"net/http"
	"strings"
)

func sendToLnodes(s *util.Lblock) error {
	for _, lnode := range Lnodes {
		_, err := http.Post(lnode+"/lblocks/new", "application/json", strings.NewReader(util.ToJSON(s)))
		if err != nil {
			return err
		}
	}
	return nil
}

func handleWriteLblock(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	b := new(util.Lblock)

	decoder := json.NewDecoder(io.LimitReader(r.Body, 1e6))
	if err := decoder.Decode(b); err != nil {
		//fmt.Println("Bad JSON request. This may be caused by a block that is too big (more than 1mb) but these are usually with malicious intent. " + err.Error())
		respondWithJSON(w, http.StatusBadRequest, "Bad JSON request. This may be caused by a block that is too big (more than 1mb) but these are usually with malicious intent. "+err.Error())
		return
	}

	fmt.Println("Received a new lblock from " + r.RemoteAddr + ":\n" + util.ToJSON(b))

	//if err := isValid(b, NewestBlock); err == nil {
	//	addBlockToChain(b)
	//} else {
	//	respondWithJSON(w, http.StatusBadRequest, "Invalid block. "+err.Error())
	//	fmt.Println("Rejected a block")
	//	return
	//}
	respondWithJSON(w, http.StatusCreated, "Lblock accepted.")
}
