package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/jwalton/gchalk"
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
	// Difficulty is how many zeros are needed in front of a block hash to be consideBrightRed a valid block. Thus, this controls how much work miners have to do.
	Difficulty = 5
	helpMsg    = `Duckcoin - quack money
Usage: duckcoin [<num of blocks>] [-t/--to <pubkey>] [-a/--amount <quacks>] [-m/--message <msg>]
When run without arguments, Duckcoin mines Quacks to the key in ~/.config/duckcoin/pubkey.pem
Examples:
   duckcoin
   duckcoin 4 # mines 4 blocks
   duckcoin 1 -t nSvl+K7RauJ5IagU+ID/slhDoR+435+NSLHOXzFBRmo= -a 3 -m "Payment of 3 Quacks to Ishan"`

	amount          int
	receiver        string
	address         string
	data            string
	numOfBlocks     = math.MaxInt64
	pubkey, privkey string
)

// A Block is a data structure that represents a validated set of transactions with proof of work, which makes it really hard to rewrite the blockchain.
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

// A Transaction is a transfer of any amount of duckcoins from one address to another.
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

func main() {
	var err error

	if ok, _ := argsHaveOption("help", "h"); ok {
		fmt.Println(helpMsg)
		return
	}
	if ok, i := argsHaveOption("to", "t"); ok {
		if len(os.Args) < i+2 {
			fmt.Println("Too few arguments to --to")
			return
		}
		receiver = os.Args[i+1]
	}
	if ok, i := argsHaveOption("message", "m"); ok {
		if len(os.Args) < i+2 {
			fmt.Println("Too few arguments to --message")
			return
		}
		data = os.Args[i+1]
	}
	if ok, i := argsHaveOption("amount", "a"); ok {
		if len(os.Args) < i+2 {
			fmt.Println("Too few arguments to --amount")
			return
		}
		amount, err = strconv.Atoi(os.Args[i+1])
		if err != nil {
			fmt.Println(err)
			return
		}
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
	address = duckToAddress(pubkey)
	fmt.Printf("Mining to this address: %s\n", gchalk.BrightBlue(address))

	loadDifficultyAndURL()

	mine(numOfBlocks, data, receiver, amount)
}

// mine mines numOfBlocks blocks, with the arbitrary data field set to data. It also takes in the receiver's address and amount to send in each block, if the block should contain a transaction.
func mine(numOfBlocks int, data string, receiver string, amount int) {
	var i int
	var b Block
	for ; i < numOfBlocks; i++ {
		doneChan := make(chan interface{}, 1)
		blockChan := make(chan Block, 1)
		r, err := http.Get(url + "/blocks/newest")
		if err != nil {
			fmt.Println(err)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		_ = r.Body.Close()
		go func() {
			blockChan <- b
			makeBlock(blockChan, privkey, "Mined by the official Duckcoin CLI User: "+username, address, Transaction{data, address, receiver, amount, pubkey, ""})
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

// duckToAddress converts a Duckcoin public key to a Duckcoin address.
func duckToAddress(duckkey string) string {
	hash := sha256.Sum256([]byte(duckkey))
	return b64(hash[:])
}

// makeBlock creates one new block by accepting the last block on blockChan, and restarting mining in case a new block is sent. It takes in the user's private key to be used in signing tx, the transaction, if tx.Amount is not 0. It also takes in the arbitrary data to be included in the block and the user's address (solver).
func makeBlock(blockChan chan Block, privkey string, data string, solver string, tx Transaction) {
	oldBlock := <-blockChan

	var newBlock Block

	t := time.Now()
Start:
	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.UnixNano() / 1000
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
			if !isHashSolution(calculateHash(newBlock)) {
				if i&(1<<17-1) == 0 && i != 0 { // optimize to check every 131072 iterations (bitwise ops are faster)
					fmt.Printf("Approx hashrate: %0.2f. Have checked %d hashes.\n", float64(i)/time.Since(t).Seconds(), i)
				}
				continue
			} else {
				fmt.Println("\nBlock made! It took", time.Since(t).Round(time.Second/100))
				newBlock.Hash = calculateHash(newBlock)
				if newBlock.Tx.Amount != 0 {
					signature, err := makeSignature(privkey, newBlock.Hash)
					if err != nil {
						fmt.Println(err)
						return
					}
					newBlock.Tx.Signature = signature
				}
				fmt.Println(gchalk.BrightYellow(toJSON(newBlock)))
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

// b64 encodes a byte array to a base64 string
func b64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func makeKeyPair() (pub string, priv string, err error) {
	pubkeyCurve := elliptic.P256()                              // see http://golang.org/pkg/crypto/elliptic/#P256
	privkey, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader) // this generates a public & private key pair

	if err != nil {
		return "", "", err
	}
	pubkey := &privkey.PublicKey
	pub, err = publicKeytoduck(pubkey)
	if err != nil {
		return "", "", err
	}
	priv, err = privateKeytoduck(privkey)
	if err != nil {
		return "", "", err
	}
	return pub, priv, nil
}

// duckToPrivateKey returns a deserialized base64 encoded private key
func duckToPrivateKey(duckkey string) (*ecdsa.PrivateKey, error) {
	d, err := base64.StdEncoding.DecodeString(duckkey)
	if err != nil {
		return nil, err
	}
	p, err := x509.ParseECPrivateKey(d)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// publicKeytoduck returns a serialized public key as a base64 string
func publicKeytoduck(pubkey *ecdsa.PublicKey) (string, error) {
	marshalled, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	return b64(marshalled), nil
}

// privateKeytoduck returns a serialized private key as a base64 string
func privateKeytoduck(privkey *ecdsa.PrivateKey) (string, error) {
	marshalled, err := x509.MarshalECPrivateKey(privkey)
	if err != nil {
		return "", err
	}
	return b64(marshalled), nil
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
	// see comment in saveKeyPair for why the keys are base64 encoded before passed to duckTo*Key
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

// makeSignature signs the given data with the given private key
func makeSignature(privkey string, message string) (string, error) {
	hash := sha256.Sum256([]byte(message))
	key, err := duckToPrivateKey(privkey)
	if err != nil {
		return "", err
	}
	data, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return "", err
	}
	return b64(data), nil
}

// The calculateHash function is used to calculate the hash of a block, this is used in the creation of the blockchain
func calculateHash(block Block) string {
	block.Hash = ""
	block.Tx.Signature = ""
	return shasum([]byte(toJSON(block)))
}

func shasum(record []byte) string {
	h := sha256.New()
	h.Write(record)
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

// isHashSolution checks if a hash is a valid block hash using the global Difficulty
func isHashSolution(hash string) bool {
	prefix := strings.Repeat("0", Difficulty)
	return strings.HasPrefix(hash, prefix)
}

func toJSON(v interface{}) string {
	s, _ := json.MarshalIndent(v, "", "   ")
	return string(s)
}

func argsHaveOption(long string, short string) (hasOption bool, foundAt int) {
	for i, arg := range os.Args {
		if arg == "--"+long || arg == "-"+short {
			return true, i
		}
	}
	return false, 0
}
