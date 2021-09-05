module duckcoin

go 1.16

replace github.com/quackduck/duckcoin/util => ./../util

require (
	github.com/gorilla/mux v1.8.0
	github.com/quackduck/duckcoin/util latest
)
