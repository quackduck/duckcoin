module duckcoin

go 1.16

replace github.com/quackduck/duckcoin/util => ./../util

require (
	github.com/jwalton/gchalk v1.3.0
	github.com/quackduck/duckcoin/util v0.0.0-20220505173723-18f9d63e034c
	golang.org/x/term v0.0.0-20220526004731-065cf7ba2467 // indirect
)
