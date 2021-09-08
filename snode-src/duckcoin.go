package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
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
	url         = "http://devzat.hackclub.com:8080"
	home, _     = os.UserHomeDir()
	u, _        = user.Current()
	username    = u.Name
	configDir   = home + "/.config/duckcoin"
	pubkeyFile  = configDir + "/pubkey.pem"
	privkeyFile = configDir + "/privkey.pem"
	urlFile     = configDir + "/url.txt"
	// Difficulty is how many zeros are needed in front of a block hash to be considred. a valid block. Thus, this controls how much work miners have to do.
	Difficulty = 5
	helpMsg    = `Duckcoin - quack money
Usage: duckcoin [<num of blocks>] [-t/--to <pubkey> -a/--amount <quacks> -m/--message <msg>]
When run without arguments, Duckcoin mines Quacks to the key in ~/.config/duckcoin/pubkey.pem
Examples:
   duckcoin
   duckcoin 4 # mines 4 blocks
   duckcoin 1 -t nSvl+K7RauJ5IagU+ID/slhDoR+435+NSLHOXzFBRmo= -a 3 -m "Payment of 3 Quacks to Ishan"`

	amount            int
	receiver          string
	address           string
	data              string
	numOfBlocks       = math.MaxInt64
	pubkey, privkey   string
	duckToMicroquacks = 1e7
)

func main() {
	var err error

	if ok, _ := util.ArgsHaveOption("help", "h"); ok {
		fmt.Println(helpMsg)
		return
	}
	if ok, i := util.ArgsHaveOption("to", "t"); ok {
		if len(os.Args) < i+2 {
			fmt.Println("Too few arguments to --to")
			return
		}
		receiver = os.Args[i+1]
	}
	if ok, i := util.ArgsHaveOption("message", "m"); ok {
		if len(os.Args) < i+2 {
			fmt.Println("Too few arguments to --message")
			return
		}
		data = os.Args[i+1]
	}
	if ok, i := util.ArgsHaveOption("amount", "a"); ok {
		if len(os.Args) < i+2 {
			fmt.Println("Too few arguments to --amount")
			return
		}
		var preConvAmmount float64
		preConvAmmount, err = strconv.ParseFloat(os.Args[i+1], 64)
		if err != nil {
			fmt.Println(err)
			return
		}

		amount = int(preConvAmmount * duckToMicroquacks)

		fmt.Println(amount)
	}
	if len(os.Args) > 1 {
		i, err := strconv.Atoi(os.Args[1])
		if err == nil {
			numOfBlocks = i
		} else {
			fmt.Println(err)
			return
		}
	}

	err = os.MkdirAll(configDir, 0700)
	if err != nil {
		fmt.Println(err)
		return
	}
	pubkey, privkey, err = loadKeyPair(pubkeyFile, privkeyFile)
	if err != nil {
		fmt.Println("Making you a fresh, new key pair and address!")
		pubkey, privkey, err = makeKeyPair()
		if err != nil {
			fmt.Println(err)
			return
		}
		err = saveKeyPair(pubkey, privkey, pubkeyFile, privkeyFile)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	address = util.DuckToAddress(pubkey)
	fmt.Printf("Mining to this address: %s\n", gchalk.BrightBlue(address))

	loadDifficultyAndURL()

	mine(numOfBlocks, data, receiver, amount)
}

// mine mines numOfBlocks blocks, with the arbitrary data field set to data. It also takes in the receiver's address and amount to send in each block, if the block should contain a transaction.
func mine(numOfBlocks int, data string, receiver string, amount int) {
	var i int
	var b util.Block
	for ; i < numOfBlocks; i++ {
		doneChan := make(chan interface{}, 1)
		blockChan := make(chan util.Block, 1)
		r, err := http.Get(url + "/blocks/newest")
		if err != nil {
			fmt.Println(err)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		_ = r.Body.Close()
		go func() {
			blockChan <- b
			makeBlock(blockChan, privkey, "Mined by the official Duckcoin CLI User: "+username, address, util.Transaction{data, address, receiver, int64(amount), pubkey, ""})
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
				r, err := http.Get(url + "/blocks/newest")
				if err != nil {
					fmt.Println(err)
					return
				}
				_ = json.NewDecoder(r.Body).Decode(&currBlock)
				_ = r.Body.Close()
				if currBlock != b {
					if currBlock.Solver != address {
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

// loadDifficultyAndURL loads the server URL from the config file, and then loads the difficulty by contacting that server.
func loadDifficultyAndURL() {
	data, err := ioutil.ReadFile(urlFile)
	if err != nil {
		ioutil.WriteFile(urlFile, []byte(url), 0644)
		return
	}
	url = strings.TrimSpace(string(data))

	r, err := http.Get(url + "/difficulty")
	if err != nil {
		fmt.Println(err)
		return
	}
	_ = json.NewDecoder(r.Body).Decode(&Difficulty)
	_ = r.Body.Close()
}

// makeBlock creates one new block by accepting the last block on blockChan, and restarting mining in case a new block is sent. It takes in the user's private key to be used in signing tx, the transaction, if tx.Amount is not 0. It also takes in the arbitrary data to be included in the block and the user's address (solver).
func makeBlock(blockChan chan util.Block, privkey string, data string, solver string, tx util.Transaction) {
	oldBlock := <-blockChan

	var newBlock util.Block

	t := time.Now()
Start:
	hashingStartTime := time.Now()
	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.UnixNano() / 1000 // TODO: change this to millis (micros right now)
	newBlock.Data = data
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Solver = solver
	newBlock.Tx = tx
	if newBlock.Tx.Amount == 0 {
		newBlock.Tx.Receiver = ""
		newBlock.Tx.Sender = ""
		newBlock.Tx.PubKey = ""
		newBlock.Tx.Signature = ""
	}
Mine:
	for i := 0; ; i++ {
		select {
		case b := <-blockChan:
			if oldBlock != b {
				oldBlock = b
				goto Start
			}
		default:
			newBlock.Solution = strconv.Itoa(i)
			if !util.IsHashSolution(util.CalculateHash(newBlock), Difficulty) {
				if i&(1<<17-1) == 0 && i != 0 { // optimize to check every 131072 iterations (bitwise ops are faster)
					fmt.Printf("Approx hashrate: %0.2f. Have checked %d hashes.\n", float64(i)/time.Since(hashingStartTime).Seconds(), i)
				}
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
				r, err := http.Post(url+"/blocks/new", "application/json", bytes.NewReader(j))
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
				r.Body.Close()
				break Mine
			}
		}
	}
	return
}

func makeKeyPair() (pub string, priv string, err error) {
	pubkeyCurve := elliptic.P256()                              // see http://golang.org/pkg/crypto/elliptic/#P256
	privkey, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader) // this generates a public & private key pair

	if err != nil {
		return "", "", err
	}
	pubkey := &privkey.PublicKey
	pub, err = util.PublicKeytoDuck(pubkey)
	if err != nil {
		return "", "", err
	}
	priv, err = util.PrivateKeytoDuck(privkey)
	if err != nil {
		return "", "", err
	}
	return pub, priv, nil
}

// saveKeyPair saves a key pair to a file using the PEM format
func saveKeyPair(pubkey string, privkey string, pubfile string, privfile string) error {
	// saveKeyPair decodes the keys because PEM base64s them too, and decoding means that the pubkey in duck format is the same as the data in the PEM file. (which is nice but an arbitrary decision)
	d, _ := base64.StdEncoding.DecodeString(privkey)
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "DUCKCOIN (ECDSA) PRIVATE KEY",
		Bytes: d,
	})
	if err := ioutil.WriteFile(privfile, b, 0600); err != nil {
		return err
	}

	d, _ = base64.StdEncoding.DecodeString(pubkey)
	b = pem.EncodeToMemory(&pem.Block{
		Type:  "DUCKCOIN (ECDSA) PUBLIC KEY",
		Bytes: d,
	})
	if err := ioutil.WriteFile(pubfile, b, 0644); err != nil {
		return err
	}

	gchalk.BrightYellow("Your keys have been saved to " + pubfile + "(pubkey) and " + privfile + " (privkey)")
	gchalk.BrightRed("Do not tell anyone what's inside " + privfile)
	return nil
}

func loadKeyPair(pubfile string, privfile string) (pub string, priv string, err error) {
	// see comment in util.SaveKeyPair for why the keys are base64 encoded before returning
	data, err := ioutil.ReadFile(pubfile)
	if err != nil {
		return "", "", err
	}
	key, _ := pem.Decode(data)
	if key == nil {
		return "", "", errors.New("could not decode PEM data from " + pubfile)
	}
	pubkey := base64.StdEncoding.EncodeToString(key.Bytes)
	data, err = ioutil.ReadFile(privfile)
	if err != nil {
		return "", "", err
	}
	key, _ = pem.Decode(data)
	if key == nil {
		return "", "", errors.New("could not decode PEM data from " + privfile)
	}
	privkey := base64.StdEncoding.EncodeToString(key.Bytes)
	gchalk.BrightYellow("Loaded keys from " + pubfile + " and " + privfile)
	return pubkey, privkey, nil
}
