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

	newestIsGenesis = false // TODO: store genesis as a normal block
	genesis         = &Block{
		Index:     0,
		Timestamp: 1620739059,
		Data: "Genesis block. Made by Ishan Goel, @quackduck on GitHub. " +
			"Thank you to Jason Antwi-Appah for the incredible name that is Duckcoin. " +
			"Thank you to Hack Club, and to the Internet. QUACK!",
		Hash:     "0000000000000000000000000000000000000000000000000000000000000000",
		PrevHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Solution: 42,                                     // the answer to life, the universe, and everything
		Solver:   "[Q.nSvl+K7RauJ5IagU+ID/slhDoR+hGkmF]", // replace with ishan's actual address
		Tx: Transaction{
			Data:      "Genesis transaction",
			Sender:    "[Q.nSvl+K7RauJ5IagU+ID/slhDoR+hGkmF]",
			Receiver:  "[Q.nSvl+K7RauJ5IagU+ID/slhDoR+hGkmF]",
			Amount:    100000 * 1e6,
			PubKey:    "",
			Signature: "",
		},
	}
)

func DBInit() {
	var err error
	o := bolt.DefaultOptions
	o.FreelistType = bolt.FreelistMapType
	db, err = bolt.Open("duckchain.db", 0600, o)
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
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, v := range blks {
			// store the newest block in idx -1
			newestIsGenesis = false
			if err := tx.Bucket(numToBlock).Put([]byte("newest"), serialize(v)); err != nil {
				panic(err)
				//return err
			}

			num := []byte(strconv.FormatUint(v.Index, 10)) // TODO: serialize idx num too
			if err := tx.Bucket(numToBlock).Put(num, serialize(v)); err != nil {
				panic(err)
				//return err
			}
			if err := tx.Bucket(hashToNum).Put(serializeHash(v.Hash), num); err != nil {
				panic(err)
				//return err
			}
			if v.Tx.Amount > 0 && v.Tx.Sender != v.Tx.Receiver {
				// no reward for solver so we can give that reward to the lnodes (TODO).

				senderBalanceBytes := tx.Bucket(addrToBalances).Get(serializeAddress(v.Tx.Sender))
				senderBalance, _ := binary.Uvarint(senderBalanceBytes)
				if senderBalance < v.Tx.Amount {
					panic("Insufficient balances " + fmt.Sprintf("Block Num: %d, Sender Balance: %d, Amount: %d, Sender Address: %s", v.Index, senderBalance, v.Tx.Amount, v.Tx.Sender))
				}
				senderBalance -= v.Tx.Amount

				receiverBalanceBytes := tx.Bucket(addrToBalances).Get(serializeAddress(v.Tx.Receiver))
				receiverBalance, _ := binary.Uvarint(receiverBalanceBytes)
				receiverBalance += v.Tx.Amount

				buf := make([]byte, binary.MaxVarintLen64)
				n := binary.PutUvarint(buf, senderBalance)
				if err := tx.Bucket(addrToBalances).Put(serializeAddress(v.Tx.Sender), buf[:n]); err != nil {
					panic(err)
				}
				buf = make([]byte, binary.MaxVarintLen64)
				n = binary.PutUvarint(buf, receiverBalance)
				if err := tx.Bucket(addrToBalances).Put(serializeAddress(v.Tx.Receiver), buf[:n]); err != nil {
					panic(err)
				}
			} else {
				solverBalanceBytes := tx.Bucket(addrToBalances).Get(serializeAddress(v.Solver))
				solverBalance, _ := binary.Uvarint(solverBalanceBytes)
				solverBalance += Reward
				buf := make([]byte, binary.MaxVarintLen64)
				n := binary.PutUvarint(buf, solverBalance)
				if err := tx.Bucket(addrToBalances).Put(serializeAddress(v.Solver), buf[:n]); err != nil {
					panic(err)
				}
			}
		}
		return nil
	}); err != nil {
		panic(err)
	}
}

func GetBlockByIndex(i uint64) (*Block, error) {
	if i == 0 {
		return genesis, nil
	}
	ret := new(Block)
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(numToBlock)
		data := b.Get([]byte(strconv.FormatUint(i, 10)))
		ret = deserialize(data)
		if ret == nil {
			panic("Nil deserialization at block " + strconv.FormatUint(i, 10))
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
		i, err := strconv.ParseUint(string(data), 10, 64)
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
	ret := new(Block)
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(numToBlock)
		data := b.Get([]byte("newest"))
		ret = deserialize(data)
		if ret == nil {
			panic("Nil deserialization at newest block")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return ret, nil
}

func GetBalanceByAddr(addr string) (uint64, error) {
	var ret uint64
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(addrToBalances)
		data := b.Get(serializeAddress(addr))
		ret, _ = binary.Uvarint(data)
		return nil
	}); err != nil {
		return 0, err
	}
	return ret, nil
}

func GetAllBalances() (map[string]uint64, error) {
	ret := make(map[string]uint64, 1000)
	return ret, db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(addrToBalances)
		return b.ForEach(func(addr, balanceData []byte) error {
			balance, _ := binary.Uvarint(balanceData)
			ret[deserializeAddress(addr)] = balance
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

	ret = encodeVarintBytes(ret, []byte(b.Data))

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

	buf = make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(buf, b.Solution)
	ret = append(ret, buf[:n]...)

	ret = encodeVarintBytes(ret, serializeAddress(b.Solver))
	if b.Tx.Amount != 0 {
		ret = append(ret, 1) // marker that Tx exists and should be deserialized
		ret = encodeVarintBytes(ret, []byte(b.Tx.Data), serializeAddress(b.Tx.Sender), serializeAddress(b.Tx.Receiver))

		buf = make([]byte, binary.MaxVarintLen64)
		n = binary.PutUvarint(buf, b.Tx.Amount)
		ret = append(ret, buf[:n]...)
		ret = encodeVarintBytes(ret, deb64(b.Tx.PubKey), deb64(b.Tx.Signature))
	} else {
		ret = append(ret, 0) // marker that Tx does not exist and should not be deserialized
	}
	return ret
}

func serializeAddress(addr string) []byte {
	// serialized format: version char + decoded base64
	// addr format: [Q + version char + base64(shasum(pubkey)[:20]) + ]
	return append([]byte{addr[2]}, deb64(addr[3:len(addr)-1])...)
}

func deserializeAddress(addrBytes []byte) string {
	return "[Q" + string(addrBytes[0]) + b64(addrBytes[1:]) + "]"
}

func serializeHash(hash string) []byte {
	hashInt, ok := new(big.Int).SetString(hash, 16)
	if !ok {
		panic("Setting big.Int to hash value as hexadecimal failed")
	}
	return encodeVarintBytes(make([]byte, 0, 10), hashInt.Bytes())
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
	if len(buf) == 0 {
		return nil
	}
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

	i, length = binary.Uvarint(buf)
	ret.Timestamp = i
	buf = buf[length:]
	ret.Solution = i

	buf, data = decodeVarintBytes(buf)
	ret.Solver = deserializeAddress(data)

	if buf[0] == 1 { // marker that tx data exists
		buf = buf[1:]
		buf, data = decodeVarintBytes(buf)
		ret.Tx.Data = string(data)

		buf, data = decodeVarintBytes(buf)
		ret.Tx.Sender = deserializeAddress(data)

		buf, data = decodeVarintBytes(buf)
		ret.Tx.Receiver = deserializeAddress(data)

		i, length = binary.Uvarint(buf)
		ret.Tx.Amount = i
		buf = buf[length:]

		buf, data = decodeVarintBytes(buf)
		ret.Tx.PubKey = b64(data)

		buf, data = decodeVarintBytes(buf)
		ret.Tx.Signature = b64(data)
	}
	return ret
}

func deb64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		//fmt.Println(s, err)
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
	readFrom = readFrom[dataLen:]
	return readFrom, dataBytes
}
