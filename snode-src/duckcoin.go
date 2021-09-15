package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/jwalton/gchalk" // color library
	"github.com/quackduck/duckcoin/util"
)

var (
	URL = "http://devzat.hackclub.com:8080"

	Username    = getUsername()
	PubkeyFile  = getConfigDir() + "/pubkey.pem"
	PrivkeyFile = getConfigDir() + "/privkey.pem"
	URLFile     = getConfigDir() + "/url.txt"

	// Difficulty is the number which a block hash must be less than to be valid. Thus, this controls how much work miners have to do.
	// It is initially set to requiring 5 hexadecimal zeros at the start (the miner does sync to the server's actual difficulty)
	Difficulty, _ = new(big.Int).SetString("00001"+strings.Repeat("0", 64-5), 16)
	Pubkey        string
	Privkey       string
	Address       string

	ArgReceiver    string // command line arguments
	ArgMessage     string
	ArgAmount      int64
	ArgNumOfBlocks int64 = math.MaxInt64

	HelpMsg = `Duckcoin - quack money

Usage: duckcoin [-h/--help]
       duckcoin [<num of blocks>] [-s/--hide-user] [-t/--to <pubkey>] 
                [-a/--amount <quacks>] [-m/--message <msg>]

Duckcoin mines for the keypair in ~/.config/duckcoin. If the --message option is
used in a block not containing a transaction, the block data field is set to it.
Otherwise, the transaction's data field is used.

Examples:
   duckcoin                                   # mine blocks continuously
   duckcoin 4 -m "Mining cause I'm bored"     # mine 4 blocks with a message
   duckcoin -s 4                              # hide your username
   duckcoin 2 -t <receiver addr> -a 7 -m "Mine 2 blocks sending 7 ducks each"
   duckcoin 1 -t nSvl+K7RauJ5IagU+ID/slhDoR+435+NSLHOXzFBRmo= -a 3.259 -m 
      "send 3.259 ducks to Ishan Goel"

For more info go to https://github.com/quackduck/duckcoin`
)

func main() {
	parseArgs()

	var err error
	Pubkey, Privkey, err = util.LoadKeyPair(PubkeyFile, PrivkeyFile)
	gchalk.BrightYellow("Loaded keys from " + PubkeyFile + " and " + PrivkeyFile)

	if err != nil {
		fmt.Println("Making you a fresh, new key pair and address!")
		Pubkey, Privkey, err = util.MakeKeyPair()
		if err != nil {
			fmt.Println(err)
			return
		}
		err = util.SaveKeyPair(Pubkey, Privkey, PubkeyFile, PrivkeyFile)
		if err != nil {
			fmt.Println(err)
			return
		}
		gchalk.BrightYellow("Your keys have been saved to " + PubkeyFile + "(pubkey) and " + PrivkeyFile + " (privkey)")
		gchalk.BrightRed("Do not tell anyone what's inside " + PrivkeyFile)
	}
	Address = util.DuckToAddress(Pubkey)
	fmt.Println("Mining to this address: ", gchalk.BrightBlue(Address))

	err = loadDifficultyAndURL()
	if err != nil {
		fmt.Println(err)
		return
	}

	blockMsg := ""
	if Username == "" {
		blockMsg = "Mined using the official Duckcoin CLI"
	} else {
		blockMsg = "Mined by the official Duckcoin CLI User: " + Username
	}
	if ArgAmount == 0 && ArgMessage != "" { // non tx block, user supplied message
		blockMsg = ArgMessage
	}

	mine(ArgNumOfBlocks, ArgAmount, ArgReceiver, blockMsg, ArgMessage)
}

// mine mines numOfBlocks blocks, with the Transaction's arbitrary data field set to data if amount is not 0.
// It also takes in the receiver's Address and amount to send in each block, if amount is not 0
func mine(numOfBlocks, amount int64, receiver, blockData, txData string) {
	var i int64
	var b util.Block
	for ; i < numOfBlocks; i++ {
		doneChan := make(chan interface{}, 1)
		blockChan := make(chan util.Block, 1)
		r, err := http.Get(URL + "/blocks/newest")
		if err != nil {
			fmt.Println(err)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		_ = r.Body.Close()
		go func() {
			blockChan <- b

			makeBlock(
				blockChan, Privkey, blockData, Address,
				util.Transaction{
					Data:      txData,
					Sender:    Address,
					Receiver:  receiver,
					Amount:    amount,
					PubKey:    Pubkey,
					Signature: "", // Signature filled in by the makeBlock function
				})

			doneChan <- true
		}()

		currBlock := b
	Monitor:
		for {
			select {
			case <-doneChan:
				break Monitor
			default:
				c := time.After(time.Second / 2)
				r, err := http.Get(URL + "/blocks/newest")
				if err != nil {
					fmt.Println(err)
					return
				}
				_ = json.NewDecoder(r.Body).Decode(&currBlock)
				_ = r.Body.Close()
				if currBlock != b {
					if currBlock.Solver != Address {
						fmt.Println(gchalk.RGB(255, 165, 0)("Gotta restart, someone else got block " + strconv.Itoa(int(currBlock.Index))))
						b = currBlock
						blockChan <- currBlock
					}
				}
				<-c
			}
		}
	}
}

// makeBlock creates one new block by accepting a block sent on blockChan as the latest block,
// and restarting mining in case a new block is sent on blockChan.
// It takes in the user's private key to be used in signing tx, the transaction, if tx.Amount is not 0.
// It also takes in the arbitrary data to be included in the block and the user's Address (solver).
//
// makeBlock also fills in the transaction's Signature field and the block's Hash field
func makeBlock(blockChan chan util.Block, privkey string, data string, solver string, tx util.Transaction) {
	oldBlock := <-blockChan

	var newBlock util.Block

	t := time.Now()
	newBlock.Timestamp = t.UnixNano() / 1e6 // convert to millis

Start:
	newBlock.Index = oldBlock.Index + 1
	newBlock.Data = data
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Solver = solver
	newBlock.Tx = tx

	if newBlock.Tx.Amount == 0 {
		newBlock.Tx.Data = ""
		newBlock.Tx.Sender = ""
		newBlock.Tx.Receiver = ""
		newBlock.Tx.PubKey = ""
		newBlock.Tx.Signature = ""
	}

	hashRateStartTime := time.Now()
	var i int64
Mine:
	for i = 0; ; i++ {
		select {
		case b := <-blockChan:
			if oldBlock != b {
				oldBlock = b
				goto Start
			}
		default:
			newBlock.Solution = strconv.FormatInt(i, 10)
			if i&(1<<17-1) == 0 && i != 0 { // optimize to check every 131072 iterations (bitwise ops are faster)
				fmt.Printf("Approx hashrate: %0.2f. Have checked %d hashes.\n", float64(i)/time.Since(hashRateStartTime).Seconds(), i)
			}
			if !util.IsHashSolutionBytes(util.CalculateHashBytes(newBlock), Difficulty) {
				continue
			} else {
				fmt.Println("\nBlock made! It took", time.Since(t).Round(time.Second/100))
				newBlock.Hash = util.CalculateHash(newBlock)
				if newBlock.Tx.Amount != 0 {
					signature, err := util.MakeSignature(privkey, newBlock.Hash)
					if err != nil {
						fmt.Println(err)
						return
					}
					newBlock.Tx.Signature = signature
				}
				fmt.Println(gchalk.BrightYellow(util.ToJSON(newBlock)))
				j, jerr := json.Marshal(newBlock)
				if jerr != nil {
					fmt.Println(jerr)
				}
				r, err := http.Post(URL+"/blocks/new", "application/json", bytes.NewReader(j))
				if err != nil {
					fmt.Println(err)
					return
				}
				fmt.Println("Sent block to server")
				resp, ierr := ioutil.ReadAll(r.Body)
				if ierr != nil {
					fmt.Println(ierr)
					return
				}
				fmt.Println("Server returned", gchalk.BrightGreen(string(resp)))
				_ = r.Body.Close()
				break Mine
			}
		}
	}
	return
}

// loadDifficultyAndURL loads the server URL from the config file, and then loads the difficulty by contacting that server.
func loadDifficultyAndURL() error {
	data, err := ioutil.ReadFile(URLFile)
	if err != nil {
		_ = ioutil.WriteFile(URLFile, []byte(URL), 0644)
		return nil
	}
	URL = strings.TrimSpace(string(data))

	r, err := http.Get(URL + "/difficulty")
	if err != nil {
		return err
	}
	defer r.Body.Close()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	difficultyStr := string(b)

	Difficulty, _ = new(big.Int).SetString(difficultyStr, 16)
	return nil
}

func parseArgs() {
	if ok, _ := util.ArgsHaveOption("help", "h"); ok {
		fmt.Println(HelpMsg)
		return
	}
	if ok, i := util.ArgsHaveOption("to", "t"); ok {
		if len(os.Args) < i+2 {
			fmt.Println("Too few arguments to --to")
			return
		}
		ArgReceiver = os.Args[i+1]

		if !util.IsValidBase64(ArgReceiver) || len(ArgReceiver) != 44 {
			fmt.Println("error: invalid receiver address")
			return
		}
	}
	if ok, _ := util.ArgsHaveOption("hide-user", "s"); ok {
		Username = ""
		return
	}
	if ok, i := util.ArgsHaveOption("message", "m"); ok {
		if len(os.Args) < i+2 {
			fmt.Println("Too few arguments to --message")
			return
		}
		ArgMessage = os.Args[i+1]
	}
	if ok, i := util.ArgsHaveOption("amount", "a"); ok {
		if len(os.Args) < i+2 {
			fmt.Println("Too few arguments to --amount")
			return
		}
		ducks, err := strconv.ParseFloat(os.Args[i+1], 64)
		if err != nil {
			fmt.Println(err)
			return
		}
		ArgAmount = int64(ducks * float64(util.MicroquacksPerDuck))
	}
	if len(os.Args) > 1 {
		i, err := strconv.ParseInt(os.Args[1], 10, 64)
		if err == nil {
			ArgNumOfBlocks = i
		} else {
			fmt.Println(err)
			return
		}
	}
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

func getUsername() string {
	u, err := user.Current()
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(0)
	}
	return u.Username
}
