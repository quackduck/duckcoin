package util

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"math/big"
	"strconv"
)

var (
	db             *bolt.DB
	numToBlock     = []byte("num -> block")
	hashToNum      = []byte("hash -> num")
	addrToBalances = []byte("addr -> balances")

	Reward uint64 = 1e6

	newestIsGenesis = false
	genesis         = &Block{
		Index:     0,
		Timestamp: 1620739059,
		Data:      "Genesis block. Thank you so much to Jason Antwi-Appah for the incredible name that is Duckcoin. QUACK!",
		Hash:      "d01bfc928a8d9523e239efd6db0d3c36cc2be9a1b0d58a3af5854ab1751b5723",
		PrevHash:  "🐤",
		Solution:  "Go Gophers and DUCKS! github.com/quackduck",
		Solver:    "Ishan Goel (quackduck on GitHub)",
		Tx: Transaction{
			Data: "Genesis transaction",
		},
	}
)

func DBInit() {
	var err error
	o := bolt.DefaultOptions
	o.FreelistType = bolt.FreelistMapType
	db, err = bolt.Open("chaindata.bolt.db", 0600, o)
	if err != nil {
		panic(err)
	}

	if err = db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(numToBlock) == nil {
			newestIsGenesis = true
		}
		_, err := tx.CreateBucketIfNotExists(numToBlock)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists(hashToNum)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists(addrToBalances)
		return err
	}); err != nil {
		panic(err)
	}
}

func WriteBlockDB(blks ...*Block) {
	newestIsGenesis = false
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, v := range blks {
			// store the newest block in idx -1
			if err := tx.Bucket(numToBlock).Put([]byte("-1"), serialize(v)); err != nil {
				panic(err)
				//return err
			}
			num := []byte(strconv.FormatInt(int64(v.Index), 10)) // TODO: serialize num too
			if err := tx.Bucket(numToBlock).Put(num, serialize(v)); err != nil {
				panic(err)
				//return err
			}
			if err := tx.Bucket(hashToNum).Put(serializeHash(v.Hash), num); err != nil {
				panic(err)
				//return err
			}
			if v.Tx.Amount > 0 {
				// no reward for solver so we can give that reward to the lnodes (TODO).

				senderBalanceBytes := tx.Bucket(addrToBalances).Get(deb64(v.Tx.Sender))
				senderBalance, _ := binary.Uvarint(senderBalanceBytes)
				if senderBalance < v.Tx.Amount {
					panic("Insufficient balances " + fmt.Sprintf("Block Num: %d, Sender Balance: %d, Amount: %d, Sender Address: %s", v.Index, senderBalance, v.Tx.Amount, v.Tx.Sender))
				}
				senderBalance -= v.Tx.Amount

				receiverBalanceBytes := tx.Bucket(addrToBalances).Get(deb64(v.Tx.Receiver))
				receiverBalance, _ := binary.Uvarint(receiverBalanceBytes)
				receiverBalance += v.Tx.Amount

				buf := make([]byte, binary.MaxVarintLen64)
				n := binary.PutUvarint(buf, senderBalance)
				if err := tx.Bucket(addrToBalances).Put(deb64(v.Tx.Sender), buf[:n]); err != nil {
					panic(err)
				}
				buf = make([]byte, binary.MaxVarintLen64)
				n = binary.PutUvarint(buf, receiverBalance)
				if err := tx.Bucket(addrToBalances).Put(deb64(v.Tx.Receiver), buf[:n]); err != nil {
					panic(err)
				}
			} else {
				solverBalanceBytes := tx.Bucket(addrToBalances).Get(deb64(v.Solver))
				solverBalance, _ := binary.Uvarint(solverBalanceBytes)
				solverBalance += Reward
				buf := make([]byte, binary.MaxVarintLen64)
				n := binary.PutUvarint(buf, solverBalance)
				if err := tx.Bucket(addrToBalances).Put(deb64(v.Solver), buf[:n]); err != nil {
					panic(err)
				}
			}
		}
		return nil
	}); err != nil {
		panic(err)
	}
}

func GetBlockByIndex(i int64) (*Block, error) {
	if i == 0 {
		return genesis, nil
	}
	ret := new(Block)
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(numToBlock)
		data := b.Get([]byte(strconv.FormatInt(i, 10)))
		ret = deserialize(data)
		if ret == nil {
			panic("Nil deserialization at block " + strconv.FormatInt(i, 10))
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return ret, nil
}

func GetBlockByHash(hash string) (*Block, error) {
	ret := new(Block)
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(hashToNum)
		data := b.Get(serializeHash(hash))
		i, err := strconv.ParseInt(string(data), 10, 64)
		if err != nil {
			return err
		}
		ret, err = GetBlockByIndex(i)
		return err
	}); err != nil {
		return nil, err
	}
	return ret, nil
}

func GetNewestBlock() (*Block, error) {
	if newestIsGenesis {
		return genesis, nil
	}
	return GetBlockByIndex(-1)
}

func GetBalanceByAddr(addr string) (uint64, error) {
	var ret uint64
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(addrToBalances)
		data := b.Get(deb64(addr))
		ret, _ = binary.Uvarint(data)
		return nil
	}); err != nil {
		return 0, err
	}
	return ret, nil
}

//func GetBalanceByAddrFloat(addr string) (float64, error) {
//	f, err := GetBalanceByAddr(addr)
//	return float64(f), err
//}

func GetAllBalances() (map[string]uint64, error) {
	ret := make(map[string]uint64, 1000)
	return ret, db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(addrToBalances)
		return b.ForEach(func(addr, balanceData []byte) error {
			balance, _ := binary.Uvarint(balanceData)
			ret[b64(addr)] = balance
			return nil
		})
	})
}

func GetAllBalancesFloats() map[string]float64 {
	l, _ := GetAllBalances()
	balances := make(map[string]float64, len(l))
	for address, balance := range l {
		balances[address] = float64(balance) / float64(MicroquacksPerDuck)
	}
	return balances
}

func serialize(b *Block) []byte {
	ret := make([]byte, 0, 1024)

	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, b.Index)
	ret = append(ret, buf[:n]...)

	buf = make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(buf, b.Timestamp)
	ret = append(ret, buf[:n]...)

	buf = make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(buf, uint64(len(b.Data)))
	ret = append(ret, buf[:n]...)

	ret = append(ret, b.Data...)

	hash, ok := new(big.Int).SetString(b.Hash, 16)
	if !ok {
		panic("Setting big.Int to hash value as hexadecimal failed")
	}
	hashBytes := hash.Bytes()
	ret = encodeVarintBytes(ret, hashBytes)

	hash, ok = new(big.Int).SetString(b.PrevHash, 16)
	if !ok {
		panic("Setting big.Int to hash value as hexadecimal failed")
	}
	hashBytes = hash.Bytes()
	ret = encodeVarintBytes(ret, hashBytes)

	//defer func() {
	//	if v := recover(); v != nil {
	//		fmt.Println("Panicked!!! at block number " + fmt.Sprint(b.Index, b, toJSON(b)))
	//		os.Exit(0)
	//	}
	//}()

	ret = encodeVarintBytes(ret, []byte(b.Solution), deb64(b.Solver))
	//fmt.Println("Now writing tx data. Current len:", len(ret))
	ret = encodeVarintBytes(ret, []byte(b.Tx.Data), deb64(b.Tx.Sender), deb64(b.Tx.Receiver))

	buf = make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(buf, uint64(b.Tx.Amount))
	ret = append(ret, buf[:n]...)
	ret = encodeVarintBytes(ret, deb64(b.Tx.PubKey), deb64(b.Tx.Signature))
	//fmt.Println("Final len:", len(ret))
	return ret
}

func serializeHash(hash string) []byte {
	hashInt, ok := new(big.Int).SetString(hash, 16)
	if !ok {
		panic("Setting big.Int to hash value as hexadecimal failed")
	}
	return encodeVarintBytes(make([]byte, 0, 10), hashInt.Bytes())
}

func deserializeHash(b []byte) string {
	_, data := decodeVarintBytes(b)
	return fmt.Sprintf("%064s", new(big.Int).SetBytes(data).Text(16))
}

func encodeVarintBytes(writeTo []byte, data ...[]byte) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	for _, elem := range data {
		buf = make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(buf, uint64(len(elem)))
		writeTo = append(writeTo, buf[:n]...)
		writeTo = append(writeTo, elem...)
	}
	return writeTo
}

func deserialize(buf []byte) *Block {
	var data []byte
	ret := new(Block)

	i, length := binary.Uvarint(buf)
	ret.Index = i
	buf = buf[length:]

	i, length = binary.Uvarint(buf)
	ret.Timestamp = i
	buf = buf[length:]

	buf, data = decodeVarintBytes(buf)
	ret.Data = string(data)

	buf, data = decodeVarintBytes(buf)
	ret.Hash = fmt.Sprintf("%064s", new(big.Int).SetBytes(data).Text(16))

	buf, data = decodeVarintBytes(buf)
	ret.PrevHash = fmt.Sprintf("%064s", new(big.Int).SetBytes(data).Text(16))

	buf, data = decodeVarintBytes(buf)
	ret.Solution = string(data)

	buf, data = decodeVarintBytes(buf)
	ret.Solver = b64(data)

	buf, data = decodeVarintBytes(buf)
	ret.Tx.Data = string(data)

	buf, data = decodeVarintBytes(buf)
	ret.Tx.Sender = b64(data)

	buf, data = decodeVarintBytes(buf)
	ret.Tx.Receiver = b64(data)

	i, length = binary.Uvarint(buf)
	ret.Tx.Amount = i
	buf = buf[length:]

	buf, data = decodeVarintBytes(buf)
	ret.Tx.PubKey = b64(data)

	buf, data = decodeVarintBytes(buf)
	ret.Tx.Signature = b64(data)
	return ret
}

func deb64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		fmt.Println(s, err, string(s[40]), []byte(s), s[40])
		panic(err)
	}
	return b
}

func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// decodeVarintStr returns the next string decoded from the format len (as varint) + string.
// It advances buf to the next thing to be read and returns it too.
func decodeVarintBytes(readFrom []byte) (newBuf []byte, data []byte) {
	i, length := binary.Uvarint(readFrom)
	dataLen := int(i)
	readFrom = readFrom[length:]
	dataBytes := make([]byte, 0, dataLen)
	dataBytes = readFrom[:dataLen]
	//ret.PrevHash = fmt.Sprintf("%064s", new(big.Int).SetBytes(hashBytes).Text(16))
	readFrom = readFrom[dataLen:]
	return readFrom, dataBytes
}
