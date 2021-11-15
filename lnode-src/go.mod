module duckcoin

go 1.16

replace github.com/quackduck/duckcoin/util => ./../util

require (
	github.com/gorilla/mux v1.8.0
	github.com/jwalton/gchalk v1.1.0
	github.com/quackduck/duckcoin/util v0.0.0-20210905224149-6373c56e4a09
)
