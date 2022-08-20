module duckcoin

go 1.18

replace github.com/quackduck/duckcoin/util => ./../util

require (
	github.com/jwalton/gchalk v1.3.0
	github.com/quackduck/duckcoin/util v0.0.0-20220505173723-18f9d63e034c
)

require (
	github.com/jwalton/go-supportscolor v1.1.0 // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	golang.org/x/sys v0.0.0-20220818161305-2296e01440c6 // indirect
	golang.org/x/term v0.0.0-20220722155259-a9ba230a4035 // indirect
)
