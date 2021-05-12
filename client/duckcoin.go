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

	"github.com/fatih/color"
)

var (
	url = "http://devzat.hackclub.com:8080"
	//url         = "http://localhost:8080"
	home, _     = os.UserHomeDir()
	u, _        = user.Current()
	username    = u.Name
	configDir   = home + "/.config/duckcoin"
	pubkeyFile  = configDir + "/pubkey.pem"
	privkeyFile = configDir + "/privkey.pem"
	Difficulty  = 5
	helpMsg     = `Duckcoin - quack money
Usage: duckcoin [<num of blocks>] [-t/--to <pubkey>] [-a/--amount <quacks>] [-m/--message <msg>]
When run without arguments, Duckcoin mines Quacks to the key in ~/.config/duckcoin/pubkey.pem
Examples:
   duckcoin
   duckcoin 4 # mines 4 blocks
   duckcoin 1 -t nSvl+K7RauJ5IagU+ID/slhDoR+435+NSLHOXzFBRmo= -a 3 -m "Payment of 1 Quack to Ishan"`
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

func main() {
	var err error
	var numOfBlocks int64
	var b Block

	amount := 0
	receiver := ""
	data := ""
	numOfBlocks = math.MaxInt64

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
		//fmt.Println("Sending to", receiver)
	}
	if ok, i := argsHaveOption("message", "m"); ok {
		if len(os.Args) < i+2 {
			fmt.Println("Too few arguments to --message")
			return
		}
		data = os.Args[i+1]
		//fmt.Println("With message", data)
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
		//fmt.Println("And amount", amount)
	}
	if len(os.Args) > 1 {
		i, err := strconv.ParseInt(os.Args[1], 10, 64)
		if err == nil {
			numOfBlocks = i
		}
	}

	os.MkdirAll(configDir, 0755)
	pubkey, privkey, err := loadKeyPair(pubkeyFile, privkeyFile)
	if err != nil {
		//fmt.Println(err)
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
	//s, _ := x509.MarshalPKIXPublicKey(solver)
	//pubkeyEncoded := publicKeytoduck(pubkey)
	//privkeyEncoded := privateKeytoduck(privkey)
	solver := duckToAddress(pubkey)
	//s, _ = x509.MarshalPKCS8PrivateKey(privkey)
	fmt.Printf("Using this key pair: \nPub: %s\nPriv: %s\nYour Address: %s\n", color.HiGreenString(pubkey), color.HiRedString(privkey), color.HiBlueString(solver))

	var i int64
	//stopChan := make(chan struct{})
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
			makeBlock(blockChan, privkey, "Mined by the official Duckcoin CLI User: "+username, solver, Transaction{data, solver, receiver, amount, pubkey, ""})
			doneChan <- true
		}()

		currBlock := b
		//oldBlock := b
	Monitor:
		for {
			select {
			case <-doneChan:
				//fmt.Println("Stopping mining")
				//close(blockChan)
				break Monitor
			default:
				c := time.After(time.Second)
				r, err := http.Get(url + "/blocks/newest")
				if err != nil {
					fmt.Println(err)
					return
				}
				_ = json.NewDecoder(r.Body).Decode(&currBlock)
				_ = r.Body.Close()
				if currBlock != b {
					//stopChan <- struct{}{}
					blockChan <- currBlock
					//fmt.Println("Going to next block")
					//i--
					//break Monitor
				}
				//fmt.Println("Monitor")
				<-c
				//time.Sleep(time.Second / 2)
			}
		}
		//fmt.Println("Next block")
		//resp, ierr := ioutil.ReadAll(r.Body)
		//if ierr != nil {
		//	fmt.Println(ierr)
		//	return
		//}
		//fmt.Println(string(resp))
	}
}

func duckToAddress(duckkey string) string {
	hash := sha256.Sum256([]byte(duckkey))
	return b64(hash[:])
}

// create a new block using previous block's hash
func makeBlock(blockChan chan Block, privkey string, data string, solver string, tx Transaction) {
	oldBlock := <-blockChan

Start:
	//stopChan := make(chan bool)
	var newBlock Block

	t := time.Now()

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
			//if b == *new(Block) {
			//	break Mine
			//}
			if oldBlock != b {
				oldBlock = b
				fmt.Println("Restart, someone already mined block number " + strconv.FormatInt(newBlock.Index, 10))
				goto Start
			}
		default:
			newBlock.Solution = strconv.Itoa(i)
			if !isHashSolution(calculateHash(newBlock)) {
				if i%100000 == 0 && i != 0 {
					fmt.Printf("Approx hashrate: %0.2f. Have checked %d hashes.\n", float64(i)/time.Since(t).Seconds(), i)
				}
				// fmt.Println(calculateHash(newBlock))
				//time.Sleep(time.Second)
				continue
			} else {
				newBlock.Hash = calculateHash(newBlock)
				if newBlock.Tx.Amount != 0 {
					signature, err := makeSignature(privkey, newBlock.Hash)
					if err != nil {
						fmt.Println(err)
						return
					}
					newBlock.Tx.Signature = signature
				}
				fmt.Println(toJson(newBlock))
				j, jerr := json.Marshal(newBlock)
				if jerr != nil {
					fmt.Println(jerr)
				}
				r, err := http.Post(url+"/blocks/new", "application/json", bytes.NewBuffer(j))
				if err != nil {
					fmt.Println(err)
				}
				fmt.Println("Sent block to server")
				r.Body.Close()
				break Mine
			}
		}
	}
	//fmt.Println("Stopping mining")
	return
}

//type ECDSASignature struct {
//	R, S *big.Int
//}

func b64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

//func keyEncode(v interface{}) string {
//	marshalled, _ := x509.MarshalPKCS8PrivateKey(v)
//	return b64(marshalled)
//}

func makeKeyPair() (pub string, priv string, err error) {
	pubkeyCurve := elliptic.P256() // see http://golang.org/pkg/crypto/elliptic/#P256
	//pubkeyCurve := elliptic.P256()
	privkey, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader) // this generates a public & private key pair

	if err != nil {
		return "", "", err
	}
	pubkey := &privkey.PublicKey
	//fmt.Println("Private Key:")
	//marshalled, _ := x509.MarshalPKCS8PrivateKey(privatekey)
	//fmt.Println(b64(marshalled))

	//fmt.Println("Public Key:")
	//marshalled, _ = x509.MarshalPKIXPublicKey(pubkey)
	//fmt.Println(b64(marshalled))
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

//// duckToPublicKey returns a deserialized base64 encoded public key
//func duckToPublicKey(duckkey string) (*ecdsa.PublicKey, error) {
//	d, err := base64.StdEncoding.DecodeString(duckkey)
//	if err != nil {
//		return nil, err
//	}
//	p, err := x509.ParsePKIXPublicKey(d)
//	if err != nil {
//		return nil, err
//	}
//	pubkey, ok := p.(*ecdsa.PublicKey)
//	if !ok {
//		return nil, errors.New("pubkey is not of type *ecdsa.PublicKey")
//	}
//	return pubkey, nil
//}

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
	//privkey, ok := p.(*ecdsa.PrivateKey)
	//if !ok {
	//	return nil, errors.New("pubkey is not of type *ecdsa.PublicKey")
	//}
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

func saveKeyPair(pubkey string, privkey string, pubfile string, privfile string) error {
	// saveKeyPair decodes the keys because PEM base64s them too, and decoding means that the pubkey in duck format is the same as the data in the PEM file. (which is nice but an arbitrary decision)
	d, _ := base64.StdEncoding.DecodeString(privkey)
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "DUCKCOIN (ECDSA) PRIVATE KEY",
		Bytes: d,
	})
	if err := ioutil.WriteFile(privfile, b, 0755); err != nil {
		return err
	}

	d, _ = base64.StdEncoding.DecodeString(pubkey)
	b = pem.EncodeToMemory(&pem.Block{
		Type:  "DUCKCOIN (ECDSA) PUBLIC KEY",
		Bytes: d,
	})
	if err := ioutil.WriteFile(pubfile, b, 0755); err != nil {
		return err
	}

	color.HiYellow("Your keys have been saved to " + pubfile + " and " + privfile)
	color.HiRed("Do not tell anyone the contents of " + privfile)
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
	color.HiYellow("Loaded keys from " + pubfile + " and " + privfile)
	return pubkey, privkey, nil
}

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
	//b := new(bytes.Buffer)
	//err = gob.NewEncoder(b).Encode(ECDSASignature{r, s})
	//if err != nil {
	//	return "", err
	//}
	//signature, err := asn1.Marshal(ECDSASignature{r, s})
	//if err != nil {
	//	return "", err
	//}
	//signature := r.Bytes()
	//signature = append(signature, s.Bytes()...)
	//fmt.Printf("Signature:" + b64(b.Bytes()))
	//fmt.Printf("hash %v key %x", hash, privatekey.PublicKey)
	return b64(data), nil
}

//type Block struct {
//	// Index is the Block number in the Icoin Blockchain
//	Index int64
//	// Timestamp is the Unix timestamp of the date of creation of this Block
//	Timestamp int64
//	// Data stores any (arbitrary) additional data.
//	Data string
//	//Hash stores the hex value of the sha256 sum of the block represented as JSON with the indent as "   " and Hash as ""
//	Hash string
//	// PrevHash is the hash of the previous Block in the Blockchain
//	PrevHash string
//	// Solution is the nonce value that makes the Hash have a prefix of Difficulty zeros
//	Solution string
//	// Solver is the public key of the sender
//	Solver string
//	// Transaction is the transaction associated with this block
//	Tx Transaction
//}
//
//type Transaction struct {
//	// Data is any (arbitrary) additional data.
//	Data string
//	//Sender is the address of the sender.
//	Sender string
//	//Receiver is the address of the receiver.
//	Receiver string
//	//Amount is the amount to be payed by the Sender to the Receiver. It is always a positive number.
//	Amount int
//	//PubKey is the Duckcoin formatted public key of the sender
//	PubKey    string
//	Signature string
//}

func calculateHash(block Block) string {
	block.Hash = ""
	block.Tx.Signature = ""
	//s :=
	return shasum([]byte(toJson(block)))
}

func shasum(record []byte) string {
	h := sha256.New()
	h.Write(record)
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func isHashSolution(hash string) bool {
	prefix := strings.Repeat("0", Difficulty)
	return strings.HasPrefix(hash, prefix)
}

func toJson(v interface{}) string {
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
