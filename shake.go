package keccak

import (
	"hash"
)

func NewSHAKE128(n int) hash.Hash {
	return newKeccak(128*2, n*8, domainSHAKE)
}

func NewSHAKE256(n int) hash.Hash {
	return newKeccak(256*2, n*8, domainSHAKE)
}
