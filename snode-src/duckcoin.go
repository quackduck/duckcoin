package main

import (
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
	"sync"
	"time"

	"github.com/jwalton/gchalk"
	"github.com/quackduck/duckcoin/util"
)

var (
	URL = "http://devzat.hackclub.com:8080"

	Username    = getUsername()
	PubkeyFile  = getConfigDir() + "/pubkey.pem"
	PrivkeyFile = getConfigDir() + "/privkey.pem"
	URLFile     = getConfigDir() + "/url.txt"

	// Difficulty is the on average number of hashes needed for a block to be valid.
	//
	// See util.GetTarget for more information on the relationship between targets and Difficulty.
	Difficulty uint64

	Pubkey  string
	Privkey string
	Addr    util.Address

	ArgReceiver    util.Address // command line arguments
	ArgMessage     string
	ArgAmount      uint64
	ArgNumOfBlocks uint64 = math.MaxUint64
	ArgThreads     uint   = 1

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

// TODO: consider sending blocks in a really efficient binary way (like BTC and probably literally every other crypto, we already have a format for the DB)

func main() {
	var err error
	parseArgs()
	Pubkey, Privkey, Addr, err = util.LoadKeysAndAddr(PubkeyFile, PrivkeyFile)
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
	gchalk.BrightYellow("Loaded keys from " + PubkeyFile + " and " + PrivkeyFile)
	fmt.Println("Mining to this address:", gchalk.BrightBlue(Addr.Emoji))

	err = loadDifficultyAndURL()
	if err != nil {
		fmt.Println(err)
		return
	}
	blockMsg := ""
	if Username == "" {
		blockMsg = ""
	} else {
		blockMsg = Username
	}
	if ArgAmount == 0 && ArgMessage != "" { // non tx block, user supplied message
		blockMsg = ArgMessage
	}

	mine(ArgNumOfBlocks, ArgAmount, ArgReceiver, blockMsg, ArgMessage)
}

// mine mines numOfBlocks blocks, with the block's data field set to blockData and the
// transaction's arbitrary data field set to txData (in this case if amount is not 0)
// It also takes in the receiver's address and amount to send in each block, used if amount is not 0
func mine(numOfBlocks, amount uint64, receiver util.Address, blockData, txData string) {
	var i uint64
	var b util.Sblock

	for ; i < numOfBlocks; i++ {
		doneChan := make(chan interface{}, 1)
		blockChan := make(chan util.Sblock, ArgThreads)
		r, err := http.Get(URL + "/sblocks/newest")
		if err != nil {
			fmt.Println(err)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		_ = r.Body.Close()
		go func() {
			blockChan <- b
			makeSblock(
				blockChan, Privkey, blockData, Addr,
				util.Transaction{
					Data:      txData,
					Sender:    Addr,
					Receiver:  receiver,
					Amount:    amount,
					PubKey:    Pubkey,
					Signature: "", // Signature filled in by the makeBlock function
				})
			close(doneChan)
		}()

		currBlock := b
	Monitor:
		for {
			select {
			case <-doneChan:
				break Monitor
			default:
				r, err := http.Get(URL + "/sblocks/newest")
				if err != nil {
					fmt.Println(err)
					return
				}
				_ = json.NewDecoder(r.Body).Decode(&currBlock)
				_ = r.Body.Close()
				//fmt.Println("Newest block:", currBlock.Index)
				if currBlock != b && currBlock.Solver != Addr { // a new block that we didn't solve?
					fmt.Println(gchalk.RGB(255, 165, 0)("Gotta restart, someone else got block " + strconv.Itoa(int(currBlock.Index))))
					b = currBlock
					for j := uint(0); j <= ArgThreads; j++ { // slightly hacky way to notify all threads to restart
						blockChan <- currBlock
					}
				}
				time.Sleep(time.Second / 2)
			}
		}
	}
}

// makeSblock creates one new block by accepting a block sent on blockChan as the latest block,
// and restarting mining in case a new block is sent on blockChan.
// It takes in the user's private key to be used in signing tx, the transaction, if tx.Amount is not 0.
// It also takes in the arbitrary data to be included in the block and the user's Addr (solver).
//
// makeSblock also fills in the transaction's Signature field and the block's Hash field
func makeSblock(blockChan chan util.Sblock, privkey string, data string, solver util.Address, tx util.Transaction) {
	err := loadDifficultyAndURL()
	if err != nil {
		fmt.Println("error: ", err)
	}
	fmt.Println(gchalk.BrightYellow(fmt.Sprint("Current difficulty: ", Difficulty)))
	target := util.GetTarget(Difficulty)
	oldBlock := <-blockChan
	stopChan := make(chan interface{})
	wg := new(sync.WaitGroup)

	for n := 1; uint(n) <= ArgThreads; n++ {
		wg.Add(1)

		go mineThreadWorker(wg, oldBlock, target, n, stopChan, blockChan, privkey, data, solver, tx)
		time.Sleep(time.Millisecond * 100) // also helps each thread have a unique timestamp
	}
	wg.Wait()
}

func mineThreadWorker(wg *sync.WaitGroup, oldBlock util.Sblock, target *big.Int, threadNum int, stop chan interface{},
	blockChan chan util.Sblock, privkey string, data string, solver util.Address, tx util.Transaction) {
	defer wg.Done()

	lastHashrate := new(float64)
	*lastHashrate = 0
	lastTime := new(time.Time)
	*lastTime = time.Now()

	newBlock := new(util.Sblock)

Restart:
	t := time.Now()
	newBlock.Timestamp = uint64(t.UnixNano() / 1000 / 1000)
	newBlock.Index = oldBlock.Index + 1
	newBlock.Data = data
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Solver = solver
	newBlock.Tx = tx

	if newBlock.Tx.Amount == 0 {
		newBlock.Tx.Data = ""
		newBlock.Tx.Sender = util.Address{}
		newBlock.Tx.Receiver = util.Address{}
		newBlock.Tx.PubKey = ""
		newBlock.Tx.Signature = ""
	}

	blockDataPreimage := newBlock.PreimageWOSolution()
Mine:
	for i := uint64(0); ; i++ { // stuff in this loop needs to be super optimized
		select {
		case b := <-blockChan:
			if oldBlock != b {
				oldBlock = b
				goto Restart
			}
		case <-stop:
			return
		default:
			newBlock.Solution = i
			if i&(1<<19-1) == 0 && i != 0 { // optimize to check every 131072*2 iterations (bitwise ops are faster)
				//fmt.Println(lastTime, lastHashrate, threadNum, i)
				statusUpdate(lastTime, lastHashrate, threadNum, i)
				//fmt.Println(lastTime, lastHashrate, threadNum, i)
			}
			if !util.IsHashValidBytes(
				util.DoubleShasumBytes(append(blockDataPreimage, strconv.FormatUint(newBlock.Solution, 10)...)),
				target) {
				continue
			} else {
				close(stop)
				fmt.Println("\nSblock made! It took", time.Since(t).Round(time.Second/100))
				//fmt.Printf("%x", util.DoubleShasumBytes(append(blockDataPreimage, strconv.FormatUint(newBlock.Solution, 10)...)))
				newBlock.Hash = newBlock.CalculateHash()
				if newBlock.Tx.Amount != 0 {
					signature, err := util.MakeSignature(privkey, newBlock.Hash)
					if err != nil {
						fmt.Println(err)
						return
					}
					newBlock.Tx.Signature = signature
				}
				fmt.Println(gchalk.BrightYellow(util.ToJSON(newBlock)))
				if sendBlock(newBlock) != nil {
					return
				}
				break Mine
			}
		}
	}
}

func statusUpdate(lastTime *time.Time, lastHashrate *float64, threadNum int, i uint64) {
	var arrow string
	curr := 1 << 19 / time.Since(*lastTime).Seconds() / 1000.0 // iterations since last time / time since last time / 1000 = kHashes
	*lastTime = time.Now()
	if *lastHashrate-curr > 50 {
		arrow = gchalk.RGB(255, 165, 0)("↓")
		*lastHashrate = curr
	} else if curr-(*lastHashrate) > 50 {
		arrow = gchalk.BrightCyan("↑")
		*lastHashrate = curr
	} else {
		arrow = " "
	}
	fmt.Printf("%d: %s Rate: %s kH/s, Checked: %s\n", threadNum, arrow, gchalk.BrightYellow(fmt.Sprintf("%d", int(math.Round(curr)))), gchalk.BrightGreen(fmt.Sprint(i)))
}

func sendBlock(newBlock *util.Sblock) error {
	r, err := http.Post(URL+"/sblocks/new", "application/json", strings.NewReader(util.ToJSON(newBlock)))
	if err != nil {
		return err
	}
	fmt.Println("Sent block to server")
	resp, ierr := ioutil.ReadAll(r.Body)
	if ierr != nil {
		return err
	}
	fmt.Println("Server returned", gchalk.BrightGreen(string(resp)), "\n")
	r.Body.Close()
	return nil
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
	difficultyInt64, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return err
	}
	Difficulty = uint64(difficultyInt64)
	return nil
}

func parseArgs() {
	if ok, i := util.ArgsHaveOption("threads", "N"); ok {
		if len(os.Args) < i+2 {
			fmt.Println("Too few arguments to --threads: need an amount to send")
			os.Exit(1)
		}
		n, err := strconv.ParseInt(os.Args[i+1], 10, 64)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		ArgThreads = uint(n)
	}
	if ok, _ := util.ArgsHaveOption("help", "h"); ok {
		fmt.Println(HelpMsg)
		os.Exit(0)
	}
	if ok, i := util.ArgsHaveOption("config", "c"); ok {
		if len(os.Args) >= i+1 { // we want the next item to be available too
			fmt.Println("Too few arguments to --config: need a directory")
			os.Exit(0)
		}
		PubkeyFile = os.Args[i+1] + "/pubkey.pem"
		PrivkeyFile = os.Args[i+1] + "/privkey.pem"
		URLFile = os.Args[i+1] + "/url.txt"
	}
	if ok, i := util.ArgsHaveOption("to", "t"); ok {
		if len(os.Args) < i+2 {
			fmt.Println("Too few arguments to --to: need an address (emoji or text)")
			os.Exit(1)
		}
		var err error
		ArgReceiver, err = util.EmojiOrTextToAddress(os.Args[i+1])
		if err != nil {
			fmt.Println("error: could not parse address: " + err.Error())
		}
		if err = ArgReceiver.IsValid(); err != nil {
			fmt.Println("error: invalid receiver address, check if you mistyped it: " + err.Error())
			os.Exit(1)
		}
	}
	if ok, _ := util.ArgsHaveOption("hide-user", "s"); ok {
		Username = ""
	}
	if ok, i := util.ArgsHaveOption("message", "m"); ok {
		if len(os.Args) < i+2 {
			fmt.Println("Too few arguments to --message: need a message")
			os.Exit(1)
		}
		ArgMessage = os.Args[i+1]
	}
	if ok, i := util.ArgsHaveOption("amount", "a"); ok {
		if len(os.Args) < i+2 {
			fmt.Println("Too few arguments to --amount: need an amount to send")
			os.Exit(1)
		}
		ducks, err := strconv.ParseFloat(os.Args[i+1], 64)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if ducks < 0 {
			fmt.Println("Can't send negative money, mate. Good try tho.")
			os.Exit(1)
		}
		ArgAmount = uint64(ducks * float64(util.MicroquacksPerDuck))
	}
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		i, err := strconv.ParseInt(os.Args[1], 10, 64)
		if err == nil {
			ArgNumOfBlocks = uint64(i) // can cause overflow with negative amounts
		} else {
			fmt.Println(err)
			os.Exit(1)
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
