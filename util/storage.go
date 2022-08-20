package util

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	bolt "go.etcd.io/bbolt"
)

var (
	db             *bolt.DB
	numToBlock     = []byte("num -> block")
	hashToNum      = []byte("hash -> num")
	addrToBalances = []byte("addr -> balances")

	Reward uint64 = 1e6

	genesis = &Sblock{
		Index:     0,
		Timestamp: 1633231790000,
		Data: "This is the genesis block. Made by Ishan Goel: @quackduck on GitHub. " +
			"Thank you to Jason Antwi-Appah for the name \"Duckcoin\", to Arcade Wise, and to Cedric Hutchings." +
			"Thank you to friends at Hack Club, and to the Internet. QUACK!",
		Hash:     "0000000000000000000000000000000000000000000000000000000000000000",
		PrevHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Solution: 42,        // the answer to life, the universe, and everything
		Solver:   Address{}, // replace with ishan's actual address
		Tx: Transaction{
			Data:      "Genesis transaction",
			Sender:    Address{},
			Receiver:  Address{},
			Amount:    100000 * 1e6,
			PubKey:    "",
			Signature: "",
		},
	}
	unconfirmedRewardMap = make(map[Address]uint64, 10)
	genesisBalances      = map[Address]uint64{
		Address{}: 1000 * MicroquacksPerDuck,
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
		_, err := tx.CreateBucketIfNotExists(numToBlock)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists(hashToNum)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists(addrToBalances)
		if err != nil {
			return err
		}

		if err := tx.Bucket(numToBlock).Put([]byte("newest"), genesis.serialize()); err != nil {
			panic(err)
			//return err
		}
		if err := tx.Bucket(numToBlock).Put([]byte("0"), genesis.serialize()); err != nil {
			panic(err)
			//return err
		}
		if err := tx.Bucket(hashToNum).Put(serializeHash(genesis.Hash), []byte("0")); err != nil {
			panic(err)
			//return err
		}
		for k, v := range genesisBalances {
			buf := make([]byte, binary.MaxVarintLen64)
			n := binary.PutUvarint(buf, v)
			err = tx.Bucket(addrToBalances).Put(k.bytes[:], buf[:n])
			if err != nil {
				return err
			}
		}
		return err
	}); err != nil {
		panic(err)
	}
	err = initUnconfirmedRewardMap()
	if err != nil {
		panic(err)
	}
}

func WriteBlockDB(blks ...*Sblock) {
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, v := range blks {
			err := updateUnconfirmedRewardMap(v.Solver, v.Index)
			if err != nil {
				return err
			}
			// store the newest block in idx -1
			//newestIsGenesis = false
			if err = tx.Bucket(numToBlock).Put([]byte("newest"), v.serialize()); err != nil {
				panic(err)
				//return err
			}

			num := []byte(strconv.FormatUint(v.Index, 10)) // TODO: serialize idx num too
			if err = tx.Bucket(numToBlock).Put(num, v.serialize()); err != nil {
				panic(err)
				//return err
			}
			if err = tx.Bucket(hashToNum).Put(serializeHash(v.Hash), num); err != nil {
				panic(err)
				//return err
			}
			if v.Tx.Amount > 0 && v.Tx.Sender != v.Tx.Receiver {
				// no reward for solver so we can give that reward to the lnodes (TODO).
				err = removeFromBalance(tx, v.Tx.Sender, v.Tx.Amount)
				if err != nil {
					return err
				}
				addToBalance(tx, v.Tx.Receiver, v.Tx.Amount)
			} else {
				addToBalance(tx, v.Solver, Reward)
			}
		}
		return nil
	}); err != nil {
		panic(err)
	}
}

func setAddressBalance(tx *bolt.Tx, address Address, balance uint64) {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, balance)
	if err := tx.Bucket(addrToBalances).Put(address.bytes[:], buf[:n]); err != nil {
		panic(err)
	}
}

func getAddressBalance(tx *bolt.Tx, address Address) uint64 {
	balanceBytes := tx.Bucket(addrToBalances).Get(address.bytes[:])
	if balanceBytes == nil {
		return 0
	}
	balance, _ := binary.Uvarint(balanceBytes)
	balance -= Reward * unconfirmedRewardMap[address] // subtract the unconfirmed reward
	return balance
}

func addToBalance(tx *bolt.Tx, address Address, delta uint64) {
	if delta == 0 {
		return
	}
	setAddressBalance(tx, address, getAddressBalance(tx, address)+delta)
}

func removeFromBalance(tx *bolt.Tx, address Address, delta uint64) error {
	if delta == 0 {
		return nil
	}
	currBalance := getAddressBalance(tx, address)
	if currBalance < delta {
		return errors.New(fmt.Sprint("insufficient balance ", currBalance, " to remove ", delta))
	}
	setAddressBalance(tx, address, currBalance-delta)
	return nil
}

func GetSblockByIndex(i uint64) (*Sblock, error) {
	ret := new(Sblock)
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(numToBlock)
		data := b.Get([]byte(strconv.FormatUint(i, 10)))
		ret = deserializeSblock(data)
		if ret == nil {
			panic("Nil deserialization at block " + strconv.FormatUint(i, 10))
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return ret, nil
}

func GetSblockByHash(hash string) (*Sblock, error) {
	ret := new(Sblock)
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(hashToNum)
		data := b.Get(serializeHash(hash))
		i, err := strconv.ParseUint(string(data), 10, 64)
		if err != nil {
			return err
		}
		ret, err = GetSblockByIndex(i)
		return err
	}); err != nil {
		return nil, err
	}
	return ret, nil
}

func GetNewestSblock() (*Sblock, error) {
	ret := new(Sblock)
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(numToBlock)
		data := b.Get([]byte("newest"))
		ret = deserializeSblock(data)
		if ret == nil {
			panic("Nil deserialization at newest block")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return ret, nil
}

func GetBalanceByAddr(addr Address) (uint64, error) {
	var ret uint64
	if err := db.View(func(tx *bolt.Tx) error {
		ret = getAddressBalance(tx, addr)
		return nil
	}); err != nil {
		return 0, err
	}
	return ret, nil
}

// GetAllBalances returns a map of addresses to the balance in microquacks
func GetAllBalances() (map[Address]uint64, error) {
	ret := make(map[Address]uint64, 1000)
	return ret, db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(addrToBalances)
		return b.ForEach(func(addr, balanceData []byte) error {
			balance, _ := binary.Uvarint(balanceData)
			address := BytesToAddress(sliceToAddrBytes(addr))
			ret[address] = balance - Reward*unconfirmedRewardMap[address]
			return nil
		})
	})
}

func initUnconfirmedRewardMap() error {
	unconfirmedRewardMap = make(map[Address]uint64, 10)
	latest, err := GetNewestSblock()
	if err != nil {
		return err
	}
	if latest.Index != 0 {
		unconfirmedRewardMap[latest.Solver]++
	}
	// get last 10 blocks excluding the latest one
	for i := latest.Index - 10; i < latest.Index && i > 0; i++ {
		block, err := GetSblockByIndex(i)
		if err != nil {
			return err
		}
		unconfirmedRewardMap[block.Solver]++
	}
	return nil
}

// allows not-counting the rewards offered by the latest 10 blocks to encourage node cooperation on longest chain
func updateUnconfirmedRewardMap(minerOfNewBlock Address, latestIndex uint64) error {
	unconfirmedRewardMap[minerOfNewBlock]++
	// get the 11th block from the top and mark as confirmed
	if latestIndex > 10 {
		block, err := GetSblockByIndex(latestIndex - 10) // eg. 0, 1 ... 10, and 11 is added. mark 1 as confirmed
		if err != nil {
			return err
		}
		unconfirmedRewardMap[block.Solver]--
	}
	return nil
}

// GetAllBalancesFloats returns a map of addresses to the balance in ducks
func GetAllBalancesFloats() map[Address]float64 {
	l, _ := GetAllBalances()
	balances := make(map[Address]float64, len(l))
	for address, balance := range l {
		balances[address] = float64(balance) / float64(MicroquacksPerDuck)
	}
	return balances
}

func (b *Sblock) serialize() []byte {
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

	ret = encodeVarintBytes(ret, b.Solver.bytes[:])
	if b.Tx.Amount != 0 {
		ret = append(ret, 1) // marker that Tx exists and should be deserialized
		ret = encodeVarintBytes(ret, []byte(b.Tx.Data), b.Tx.Sender.bytes[:], b.Tx.Receiver.bytes[:])

		buf = make([]byte, binary.MaxVarintLen64)
		n = binary.PutUvarint(buf, b.Tx.Amount)
		ret = append(ret, buf[:n]...)
		ret = encodeVarintBytes(ret, deb64(b.Tx.PubKey), deb64(b.Tx.Signature))
	} else {
		ret = append(ret, 0) // marker that Tx does not exist and should not be deserialized
	}
	return ret
}

func serializeHash(hash string) []byte {
	hashInt, ok := new(big.Int).SetString(hash, 16)
	if !ok {
		panic("Setting big.Int to hash value as hexadecimal failed")
	}
	return encodeVarintBytes(make([]byte, 0, 10), hashInt.Bytes())
}

func encodeVarintBytes(writeTo []byte, data ...[]byte) []byte {
	//buf := make([]byte, binary.MaxVarintLen64)
	var buf []byte
	for _, elem := range data {
		buf = make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(buf, uint64(len(elem)))
		writeTo = append(writeTo, buf[:n]...)
		writeTo = append(writeTo, elem...)
	}
	return writeTo
}

func deserializeSblock(buf []byte) *Sblock {
	if len(buf) == 0 {
		return nil
	}
	var data []byte
	ret := new(Sblock)

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
	ret.Solver = BytesToAddress(sliceToAddrBytes(data))

	if buf[0] == 1 { // marker that tx data exists
		buf = buf[1:]
		buf, data = decodeVarintBytes(buf)
		ret.Tx.Data = string(data)

		buf, data = decodeVarintBytes(buf)
		ret.Tx.Sender = BytesToAddress(sliceToAddrBytes(data))

		buf, data = decodeVarintBytes(buf)
		ret.Tx.Receiver = BytesToAddress(sliceToAddrBytes(data))

		i, length = binary.Uvarint(buf)
		ret.Tx.Amount = i
		buf = buf[length:]

		buf, data = decodeVarintBytes(buf)
		ret.Tx.PubKey = b64(data)

		_, data = decodeVarintBytes(buf)
		ret.Tx.Signature = b64(data)
	}
	return ret
}

func (b *Lblock) serialize() []byte {
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

	ret = encodeVarintBytes(ret, b.Solver.bytes[:])
	if len(b.Sblocks) != 0 {
		ret = append(ret, 1) // marker that Sblocks exist and should be deserialized

		blocks := make([]byte, 0, 10*len(b.Sblocks)*512)

		buf = make([]byte, binary.MaxVarintLen64)
		n = binary.PutUvarint(buf, uint64(len(b.Sblocks)))
		blocks = append(blocks, buf[:n]...)

		for _, sb := range b.Sblocks {
			blocks = encodeVarintBytes(blocks, sb.serialize())
		}
		ret = encodeVarintBytes(ret, blocks)
	} else {
		ret = append(ret, 0) // marker that sblocks do not exist and should not be deserialized
	}
	return ret
}

func deserializeLblock(buf []byte) *Lblock {
	if len(buf) == 0 {
		return nil
	}
	var data []byte
	ret := new(Lblock)

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
	ret.Solver = BytesToAddress(sliceToAddrBytes(data))

	if buf[0] == 1 { // marker that sblock data exists
		buf = buf[1:]

		_, blocks := decodeVarintBytes(buf)

		i, length = binary.Uvarint(blocks)
		ret.Sblocks = make([]*Sblock, i)
		blocks = blocks[length:]

		for j := uint64(0); j < i; j++ {
			blocks, data = decodeVarintBytes(blocks)
			ret.Sblocks[j] = deserializeSblock(data)
		}
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

// decodeVarintBytes returns the next chunk decoded from the format chunk len (as varint) + chunk.
// It advances buf to the next chunk and returns it too.
func decodeVarintBytes(readFrom []byte) (newBuf []byte, data []byte) {
	i, length := binary.Uvarint(readFrom)
	dataLen := int(i)
	readFrom = readFrom[length:]
	dataBytes := readFrom[:dataLen]
	readFrom = readFrom[dataLen:]
	return readFrom, dataBytes
}
