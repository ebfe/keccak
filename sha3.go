package keccak

import (
	"hash"
)

func NewSHA3224() hash.Hash {
	return newKeccak(224*2, 224, domainSHA3)
}

func NewSHA3256() hash.Hash {
	return newKeccak(256*2, 256, domainSHA3)
}

func NewSHA3384() hash.Hash {
	return newKeccak(384*2, 384, domainSHA3)
}

func NewSHA3512() hash.Hash {
	return newKeccak(512*2, 512, domainSHA3)
}
