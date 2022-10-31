module duckcoin

go 1.18

replace github.com/quackduck/duckcoin/util => ./../util

require (
	github.com/jwalton/gchalk v1.3.0
	github.com/quackduck/duckcoin/util v0.0.0-20221029200842-2a7ddacac189
)

require (
	github.com/jwalton/go-supportscolor v1.1.0 // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	golang.org/x/sys v0.1.0 // indirect
	golang.org/x/term v0.1.0 // indirect
)
