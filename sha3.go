package keccak

import (
	"hash"
)

func NewSHA3224() hash.Hash {
	return newKeccak(224, domainSHA3)
}

func NewSHA3256() hash.Hash {
	return newKeccak(256, domainSHA3)
}

func NewSHA3384() hash.Hash {
	return newKeccak(384, domainSHA3)
}

func NewSHA3512() hash.Hash {
	return newKeccak(512, domainSHA3)
}
