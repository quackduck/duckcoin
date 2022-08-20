package util

import (
	"crypto/ecdsa"
	"math/big"
	"reflect"
	"testing"
)

func TestAddress_IsValid(t *testing.T) {
	a := &Address{Emoji: "🦆😾📎🏥🐷🌇⛲💣🍾🌍👨🎣🤬🔅🗄💋🦿😧🦔😐", Text: "QClNW9qpw0zCYuO5q8lGU6SFQmCQ1T7EAm", bytes: [24]uint8{0xf1, 0x1, 0xe5, 0xa6, 0xc7, 0x77, 0x32, 0x4a, 0xc5, 0xbf, 0x4d, 0xba, 0xcb, 0x16, 0xc8, 0x9, 0xc8, 0xd8, 0xfb, 0x61, 0xa5, 0xbe, 0x5e, 0xee}}
	if err := a.IsValid(); err != nil {
		t.Errorf("IsValid() error = %v", err)
	}
	// invalid address: look at first byte
	a = &Address{Emoji: "🦆😾📎🏥🐷🌇⛲💣🍾🌍👨🎣🤬🔅🗄💋🦿😧🦔😐", Text: "QClNW9qpw0zCYuO5q8lGU6SFQmCQ1T7EAm", bytes: [24]uint8{0xff, 0x1, 0xe5, 0xa6, 0xc7, 0x77, 0x32, 0x4a, 0xc5, 0xbf, 0x4d, 0xba, 0xcb, 0x16, 0xc8, 0x9, 0xc8, 0xd8, 0xfb, 0x61, 0xa5, 0xbe, 0x5e, 0xee}}
	if err := a.IsValid(); err == nil {
		t.Errorf("IsValid() error = %v", err)
	}
}

func TestCheckSignature(t *testing.T) {
	type args struct {
		signature string
		pubkey    string
		message   string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckSignature(tt.args.signature, tt.args.pubkey, tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckSignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CheckSignature() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDoubleShasumBytes(t *testing.T) {
	want := []byte{0x95, 0x95, 0xc9, 0xdf, 0x90, 0x7, 0x51, 0x48, 0xeb, 0x6, 0x86, 0x3, 0x65, 0xdf, 0x33, 0x58, 0x4b, 0x75, 0xbf, 0xf7, 0x82, 0xa5, 0x10, 0xc6, 0xcd, 0x48, 0x83, 0xa4, 0x19, 0x83, 0x3d, 0x50}
	if got := DoubleShasumBytes([]byte("hello")); !reflect.DeepEqual(got, want) {
		t.Errorf("DoubleShasumBytes() = %v, want %v", got, want)
	}
}

func TestGetTarget(t *testing.T) {
	want, _ := big.NewInt(0).SetString("4000000000000000000000000000000000000000000000000000000000000", 16)
	if got := GetTarget(1 << 14); got.Cmp(want) != 0 {
		t.Errorf("GetTarget() = %v, want %v", got.Text(16), want.Text(16))
	}
}

func TestIsHashValidBytes(t *testing.T) {
	want := true
	target, _ := big.NewInt(0).SetString("4000000000000000000000000000000000000000000000000000000000000", 16)
	hashTg, _ := big.NewInt(0).SetString("3900000000000000000000000000000000000000000000000000000000000", 16)

	if got := IsHashValidBytes(hashTg.FillBytes(make([]byte, 32)), target); got != want {
		t.Errorf("IsHashValidBytes() = %v, want %v", got, want)
	}
	want = false
	hashTg, _ = big.NewInt(0).SetString("4100000000000000000000000000000000000000000000000000000000000", 16)
	if got := IsHashValidBytes(hashTg.FillBytes(make([]byte, 32)), target); got != want {
		t.Errorf("IsHashValidBytes() = %v, want %v", got, want)
	}
}

func TestIsSblockValidNoCheckDB(t *testing.T) {
	target, _ := big.NewInt(0).SetString("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 16)
	tests := []struct {
		name     string
		newBlock *Sblock
		oldBlock *Sblock
		target   *big.Int
		wantErr  bool
	}{
		{"valid",
			&Sblock{
				Index:     2,
				Timestamp: 0x181200d7a83,
				Data:      "ishan",
				Hash:      "0000008f071333349946244908d863ccd037ed0b905ffe914e0d4695d017645c",
				PrevHash:  "00000255ddf50f2f637b982d714132706cfae2f9a723ead5f20c2b4b5e94737f",
				Solution:  0x6021d3,
				Solver:    Address{Emoji: "🦆😾📎🏥🐷🌇⛲💣🍾🌍👨🎣🤬🔅🗄💋🦿😧🦔😐", Text: "QClNW9qpw0zCYuO5q8lGU6SFQmCQ1T7EAm", bytes: [24]uint8{0xf1, 0x1, 0xe5, 0xa6, 0xc7, 0x77, 0x32, 0x4a, 0xc5, 0xbf, 0x4d, 0xba, 0xcb, 0x16, 0xc8, 0x9, 0xc8, 0xd8, 0xfb, 0x61, 0xa5, 0xbe, 0x5e, 0xee}},
				Tx:        Transaction{},
			},
			&Sblock{
				Index:     1,
				Timestamp: 0x181200d74a3,
				Data:      "ishan",
				Hash:      "00000255ddf50f2f637b982d714132706cfae2f9a723ead5f20c2b4b5e94737f",
				PrevHash:  "0000000000000000000000000000000000000000000000000000000000000000",
				Solution:  0x431052,
				Solver:    Address{Emoji: "🦆😾📎🏥🐷🌇⛲💣🍾🌍👨🎣🤬🔅🗄💋🦿😧🦔😐", Text: "QClNW9qpw0zCYuO5q8lGU6SFQmCQ1T7EAm", bytes: [24]uint8{0xf1, 0x1, 0xe5, 0xa6, 0xc7, 0x77, 0x32, 0x4a, 0xc5, 0xbf, 0x4d, 0xba, 0xcb, 0x16, 0xc8, 0x9, 0xc8, 0xd8, 0xfb, 0x61, 0xa5, 0xbe, 0x5e, 0xee}},
				Tx:        Transaction{},
			},
			target,
			false,
			//{""},
		},
		{"valid with tx",
			&Sblock{
				Index:     10,
				Timestamp: 0x1812047e891,
				Data:      "ishan",
				Hash:      "0000019d96d49f7cdbcdac4f37ee77d9289c9e65508140799bea68af7650995e",
				PrevHash:  "0000004f26163127496e875fd140105676a20b55c0358000e2902775ac78b55e",
				Solution:  0x518bda,
				Solver:    Address{Emoji: "🦆😾📎🏥🐷🌇⛲💣🍾🌍👨🎣🤬🔅🗄💋🦿😧🦔😐", Text: "QClNW9qpw0zCYuO5q8lGU6SFQmCQ1T7EAm", bytes: [24]uint8{0xf1, 0x1, 0xe5, 0xa6, 0xc7, 0x77, 0x32, 0x4a, 0xc5, 0xbf, 0x4d, 0xba, 0xcb, 0x16, 0xc8, 0x9, 0xc8, 0xd8, 0xfb, 0x61, 0xa5, 0xbe, 0x5e, 0xee}},
				Tx: Transaction{
					Data:      "hello there. why are you looking at this test case?",
					Sender:    Address{Emoji: "🦆😾📎🏥🐷🌇⛲💣🍾🌍👨🎣🤬🔅🗄💋🦿😧🦔😐", Text: "QClNW9qpw0zCYuO5q8lGU6SFQmCQ1T7EAm", bytes: [24]uint8{0xf1, 0x1, 0xe5, 0xa6, 0xc7, 0x77, 0x32, 0x4a, 0xc5, 0xbf, 0x4d, 0xba, 0xcb, 0x16, 0xc8, 0x9, 0xc8, 0xd8, 0xfb, 0x61, 0xa5, 0xbe, 0x5e, 0xee}},
					Receiver:  Address{Emoji: "🦆🍩🍅💕🤧👔🦚🚥😐📬🎽💰🌹➰👒🩴😑🆓🚔👧", Text: "QCERVti9HcuKhzJn0wmlRlNGzMcsP5yK1T", bytes: [24]uint8{0xbf, 0xc5, 0x39, 0xeb, 0xe4, 0x98, 0x54, 0xbb, 0xd6, 0xe, 0x6c, 0xcd, 0x9e, 0x69, 0xd8, 0x7d, 0xc2, 0xb5, 0x5e, 0x1d, 0xa, 0xc5, 0xe0, 0x31}},
					Amount:    0x1e8480,
					PubKey:    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEonWWCXkG0K8EYkt7xv/4CkZpxY1nMpeoT51oTPfXcuYcJ/eaZVipyGfh9ZitqfOQkiDhJ/NLgBj5MB/Jr5jJyw==",
					Signature: "MEYCIQDAoCLEmcPc/SvYGCMayJPQYR2KSm+0TfGvya/yTvZtfAIhAJYdLLh+vMNBFQtmZG0JznpQIm4kvRQPg26VzWOWX0Es",
				},
			},
			&Sblock{
				Index:     9,
				Timestamp: 0x1812046a5fb,
				Data:      "Hello there. why are you looking at this test case.",
				Hash:      "0000004f26163127496e875fd140105676a20b55c0358000e2902775ac78b55e",
				PrevHash:  "0000008bdc9ea7ef38661e10e79fd714b746c4c2fcb3d306b82e3f4ce15bfbb9",
				Solution:  0x221b2,
				Solver:    Address{Emoji: "🦆😾📎🏥🐷🌇⛲💣🍾🌍👨🎣🤬🔅🗄💋🦿😧🦔😐", Text: "QClNW9qpw0zCYuO5q8lGU6SFQmCQ1T7EAm", bytes: [24]uint8{0xf1, 0x1, 0xe5, 0xa6, 0xc7, 0x77, 0x32, 0x4a, 0xc5, 0xbf, 0x4d, 0xba, 0xcb, 0x16, 0xc8, 0x9, 0xc8, 0xd8, 0xfb, 0x61, 0xa5, 0xbe, 0x5e, 0xee}},
				Tx:        Transaction{},
			},
			target,
			false,
		},
		{"invalid with tx",
			&Sblock{
				Index:     10,
				Timestamp: 0x1812047e892, // invalid timestamp, changes hash.
				Data:      "ishan",
				Hash:      "0000019d96d49f7cdbcdac4f37ee77d9289c9e65508140799bea68af7650995e",
				PrevHash:  "0000004f26163127496e875fd140105676a20b55c0358000e2902775ac78b55e",
				Solution:  0x518bda,
				Solver:    Address{Emoji: "🦆😾📎🏥🐷🌇⛲💣🍾🌍👨🎣🤬🔅🗄💋🦿😧🦔😐", Text: "QClNW9qpw0zCYuO5q8lGU6SFQmCQ1T7EAm", bytes: [24]uint8{0xf1, 0x1, 0xe5, 0xa6, 0xc7, 0x77, 0x32, 0x4a, 0xc5, 0xbf, 0x4d, 0xba, 0xcb, 0x16, 0xc8, 0x9, 0xc8, 0xd8, 0xfb, 0x61, 0xa5, 0xbe, 0x5e, 0xee}},
				Tx: Transaction{
					Data:      "hello there. why are you looking at this test case?",
					Sender:    Address{Emoji: "🦆😾📎🏥🐷🌇⛲💣🍾🌍👨🎣🤬🔅🗄💋🦿😧🦔😐", Text: "QClNW9qpw0zCYuO5q8lGU6SFQmCQ1T7EAm", bytes: [24]uint8{0xf1, 0x1, 0xe5, 0xa6, 0xc7, 0x77, 0x32, 0x4a, 0xc5, 0xbf, 0x4d, 0xba, 0xcb, 0x16, 0xc8, 0x9, 0xc8, 0xd8, 0xfb, 0x61, 0xa5, 0xbe, 0x5e, 0xee}},
					Receiver:  Address{Emoji: "🦆🍩🍅💕🤧👔🦚🚥😐📬🎽💰🌹➰👒🩴😑🆓🚔👧", Text: "QCERVti9HcuKhzJn0wmlRlNGzMcsP5yK1T", bytes: [24]uint8{0xbf, 0xc5, 0x39, 0xeb, 0xe4, 0x98, 0x54, 0xbb, 0xd6, 0xe, 0x6c, 0xcd, 0x9e, 0x69, 0xd8, 0x7d, 0xc2, 0xb5, 0x5e, 0x1d, 0xa, 0xc5, 0xe0, 0x31}},
					Amount:    0x1e8480,
					PubKey:    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEonWWCXkG0K8EYkt7xv/4CkZpxY1nMpeoT51oTPfXcuYcJ/eaZVipyGfh9ZitqfOQkiDhJ/NLgBj5MB/Jr5jJyw==",
					Signature: "MEYCIQDAoCLEmcPc/SvYGCMayJPQYR2KSm+0TfGvya/yTvZtfAIhAJYdLLh+vMNBFQtmZG0JznpQIm4kvRQPg26VzWOWX0Es",
				},
			},
			&Sblock{
				Index:     9,
				Timestamp: 0x1812046a5fb,
				Data:      "Hello there. why are you looking at this test case.",
				Hash:      "0000004f26163127496e875fd140105676a20b55c0358000e2902775ac78b55e",
				PrevHash:  "0000008bdc9ea7ef38661e10e79fd714b746c4c2fcb3d306b82e3f4ce15bfbb9",
				Solution:  0x221b2,
				Solver:    Address{Emoji: "🦆😾📎🏥🐷🌇⛲💣🍾🌍👨🎣🤬🔅🗄💋🦿😧🦔😐", Text: "QClNW9qpw0zCYuO5q8lGU6SFQmCQ1T7EAm", bytes: [24]uint8{0xf1, 0x1, 0xe5, 0xa6, 0xc7, 0x77, 0x32, 0x4a, 0xc5, 0xbf, 0x4d, 0xba, 0xcb, 0x16, 0xc8, 0x9, 0xc8, 0xd8, 0xfb, 0x61, 0xa5, 0xbe, 0x5e, 0xee}},
				Tx:        Transaction{},
			},
			target,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := IsValidNoCheckDB(tt.newBlock, tt.oldBlock, tt.target); (err != nil) != tt.wantErr {
				t.Errorf("sblock IsValidNoCheckDB() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsValidBase64(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidBase64(tt.args.s); got != tt.want {
				t.Errorf("IsValidBase64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyToAddress(t *testing.T) {
	type args struct {
		key string
	}
	tests := []struct {
		name string
		args args
		want Address
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := KeyToAddress(tt.args.key); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyToAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLblock_CalculateHashBytes(t *testing.T) {
	type fields struct {
		Index     uint64
		Timestamp uint64
		Data      string
		Hash      string
		PrevHash  string
		Solution  uint64
		Solver    Address
		Sblocks   []*Sblock
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Lblock{
				Index:     tt.fields.Index,
				Timestamp: tt.fields.Timestamp,
				Data:      tt.fields.Data,
				Hash:      tt.fields.Hash,
				PrevHash:  tt.fields.PrevHash,
				Solution:  tt.fields.Solution,
				Solver:    tt.fields.Solver,
				Sblocks:   tt.fields.Sblocks,
			}
			if got := b.CalculateHashBytes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CalculateHashBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLblock_Preimage(t *testing.T) {
	type fields struct {
		Index     uint64
		Timestamp uint64
		Data      string
		Hash      string
		PrevHash  string
		Solution  uint64
		Solver    Address
		Sblocks   []*Sblock
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Lblock{
				Index:     tt.fields.Index,
				Timestamp: tt.fields.Timestamp,
				Data:      tt.fields.Data,
				Hash:      tt.fields.Hash,
				PrevHash:  tt.fields.PrevHash,
				Solution:  tt.fields.Solution,
				Solver:    tt.fields.Solver,
				Sblocks:   tt.fields.Sblocks,
			}
			if got := b.Preimage(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Preimage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLblock_PreimageWOSolution(t *testing.T) {
	type fields struct {
		Index     uint64
		Timestamp uint64
		Data      string
		Hash      string
		PrevHash  string
		Solution  uint64
		Solver    Address
		Sblocks   []*Sblock
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Lblock{
				Index:     tt.fields.Index,
				Timestamp: tt.fields.Timestamp,
				Data:      tt.fields.Data,
				Hash:      tt.fields.Hash,
				PrevHash:  tt.fields.PrevHash,
				Solution:  tt.fields.Solution,
				Solver:    tt.fields.Solver,
				Sblocks:   tt.fields.Sblocks,
			}
			if got := b.PreimageWOSolution(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PreimageWOSolution() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLblock_serialize(t *testing.T) {
	type fields struct {
		Index     uint64
		Timestamp uint64
		Data      string
		Hash      string
		PrevHash  string
		Solution  uint64
		Solver    Address
		Sblocks   []*Sblock
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Lblock{
				Index:     tt.fields.Index,
				Timestamp: tt.fields.Timestamp,
				Data:      tt.fields.Data,
				Hash:      tt.fields.Hash,
				PrevHash:  tt.fields.PrevHash,
				Solution:  tt.fields.Solution,
				Solver:    tt.fields.Solver,
				Sblocks:   tt.fields.Sblocks,
			}
			if got := b.serialize(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("serialize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSblock_CalculateHashBytes(t *testing.T) {
	type fields struct {
		Index     uint64
		Timestamp uint64
		Data      string
		Hash      string
		PrevHash  string
		Solution  uint64
		Solver    Address
		Tx        Transaction
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Sblock{
				Index:     tt.fields.Index,
				Timestamp: tt.fields.Timestamp,
				Data:      tt.fields.Data,
				Hash:      tt.fields.Hash,
				PrevHash:  tt.fields.PrevHash,
				Solution:  tt.fields.Solution,
				Solver:    tt.fields.Solver,
				Tx:        tt.fields.Tx,
			}
			if got := b.CalculateHashBytes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CalculateHashBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSblock_Preimage(t *testing.T) {
	type fields struct {
		Index     uint64
		Timestamp uint64
		Data      string
		Hash      string
		PrevHash  string
		Solution  uint64
		Solver    Address
		Tx        Transaction
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Sblock{
				Index:     tt.fields.Index,
				Timestamp: tt.fields.Timestamp,
				Data:      tt.fields.Data,
				Hash:      tt.fields.Hash,
				PrevHash:  tt.fields.PrevHash,
				Solution:  tt.fields.Solution,
				Solver:    tt.fields.Solver,
				Tx:        tt.fields.Tx,
			}
			if got := b.Preimage(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Preimage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSblock_PreimageWOSolution(t *testing.T) {
	type fields struct {
		Index     uint64
		Timestamp uint64
		Data      string
		Hash      string
		PrevHash  string
		Solution  uint64
		Solver    Address
		Tx        Transaction
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Sblock{
				Index:     tt.fields.Index,
				Timestamp: tt.fields.Timestamp,
				Data:      tt.fields.Data,
				Hash:      tt.fields.Hash,
				PrevHash:  tt.fields.PrevHash,
				Solution:  tt.fields.Solution,
				Solver:    tt.fields.Solver,
				Tx:        tt.fields.Tx,
			}
			if got := b.PreimageWOSolution(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PreimageWOSolution() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSblock_serialize(t *testing.T) {
	type fields struct {
		Index     uint64
		Timestamp uint64
		Data      string
		Hash      string
		PrevHash  string
		Solution  uint64
		Solver    Address
		Tx        Transaction
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Sblock{
				Index:     tt.fields.Index,
				Timestamp: tt.fields.Timestamp,
				Data:      tt.fields.Data,
				Hash:      tt.fields.Hash,
				PrevHash:  tt.fields.PrevHash,
				Solution:  tt.fields.Solution,
				Solver:    tt.fields.Solver,
				Tx:        tt.fields.Tx,
			}
			if got := b.serialize(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("serialize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_deserializeLblock(t *testing.T) {
	type args struct {
		buf []byte
	}
	tests := []struct {
		name string
		args args
		want *Lblock
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deserializeLblock(tt.args.buf); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("deserializeLblock() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_deserializeSblock(t *testing.T) {
	type args struct {
		buf []byte
	}
	tests := []struct {
		name string
		args args
		want *Sblock
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deserializeSblock(tt.args.buf); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("deserializeSblock() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_duckToPrivateKey(t *testing.T) {
	type args struct {
		duckkey string
	}
	tests := []struct {
		name    string
		args    args
		want    *ecdsa.PrivateKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := duckToPrivateKey(tt.args.duckkey)
			if (err != nil) != tt.wantErr {
				t.Errorf("duckToPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("duckToPrivateKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_duckToPublicKey(t *testing.T) {
	type args struct {
		duckkey string
	}
	tests := []struct {
		name    string
		args    args
		want    *ecdsa.PublicKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := duckToPublicKey(tt.args.duckkey)
			if (err != nil) != tt.wantErr {
				t.Errorf("duckToPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("duckToPublicKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTextToAddress(t *testing.T) {
	type args struct {
		text string
	}
	tests := []struct {
		name    string
		args    args
		want    Address
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TextToAddress(tt.args.text)
			if (err != nil) != tt.wantErr {
				t.Errorf("TextToAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TextToAddress() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTextToBytes(t *testing.T) {
	type args struct {
		text string
	}
	tests := []struct {
		name    string
		args    args
		want    [addrBytesLen]byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TextToBytes(tt.args.text)
			if (err != nil) != tt.wantErr {
				t.Errorf("TextToBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TextToBytes() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_addChecksum(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := addChecksum(tt.args.data); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("addChecksum() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_verifyChecksum(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := verifyChecksum(tt.args.data); got != tt.want {
				t.Errorf("verifyChecksum() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodeVarintBytes(t *testing.T) {
	type args struct {
		readFrom []byte
	}
	tests := []struct {
		name       string
		args       args
		wantNewBuf []byte
		wantData   []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNewBuf, gotData := decodeVarintBytes(tt.args.readFrom)
			if !reflect.DeepEqual(gotNewBuf, tt.wantNewBuf) {
				t.Errorf("decodeVarintBytes() gotNewBuf = %v, want %v", gotNewBuf, tt.wantNewBuf)
			}
			if !reflect.DeepEqual(gotData, tt.wantData) {
				t.Errorf("decodeVarintBytes() gotData = %v, want %v", gotData, tt.wantData)
			}
		})
	}
}

func Test_encodeVarintBytes(t *testing.T) {
	type args struct {
		writeTo []byte
		data    [][]byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encodeVarintBytes(tt.args.writeTo, tt.args.data...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encodeVarintBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_privateKeytoDuck(t *testing.T) {
	type args struct {
		privkey *ecdsa.PrivateKey
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := privateKeytoDuck(tt.args.privkey)
			if (err != nil) != tt.wantErr {
				t.Errorf("privateKeytoDuck() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("privateKeytoDuck() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_publicKeytoDuck(t *testing.T) {
	type args struct {
		pubkey *ecdsa.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := publicKeytoDuck(tt.args.pubkey)
			if (err != nil) != tt.wantErr {
				t.Errorf("publicKeytoDuck() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("publicKeytoDuck() got = %v, want %v", got, tt.want)
			}
		})
	}
}
