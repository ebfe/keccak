// Package keccak implements the Keccak (SHA-3) hash algorithm.
// http://keccak.noekeon.org / FIPS 202 draft.
package keccak

import (
	"hash"
)

const (
	domainNone  = 1
	domainSHA3  = 0x06
	domainSHAKE = 0x1f
)

const rounds = 24

var roundConstants = []uint64{
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088,
	0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008,
}

var rotationConstants = [24]uint{
	1, 3, 6, 10, 15, 21, 28, 36,
	45, 55, 2, 14, 27, 41, 56, 8,
	25, 43, 62, 18, 39, 61, 20, 44,
}

var piLane = [24]uint{
	10, 7, 11, 17, 18, 3, 5, 16,
	8, 21, 24, 4, 15, 23, 19, 13,
	12, 2, 20, 14, 22, 9, 6, 1,
}

type keccak struct {
	S         [25]uint64
	size      int
	blockSize int
	buf       []byte
	domain    byte
}

func newKeccak(capacity, output int, domain byte) hash.Hash {
	var h keccak
	h.size = output / 8
	h.blockSize = (200 - capacity/8)
	h.domain = domain
	return &h
}

func New224() hash.Hash {
	return newKeccak(224*2, 224, domainNone)
}

func New256() hash.Hash {
	return newKeccak(256*2, 256, domainNone)
}

func New384() hash.Hash {
	return newKeccak(384*2, 384, domainNone)
}

func New512() hash.Hash {
	return newKeccak(512*2, 512, domainNone)
}

func (k *keccak) Write(b []byte) (int, error) {
	n := len(b)

	if len(k.buf) > 0 {
		x := k.blockSize - len(k.buf)
		if x > len(b) {
			x = len(b)
		}
		k.buf = append(k.buf, b[:x]...)
		b = b[x:]

		if len(k.buf) < k.blockSize {
			return n, nil
		}

		k.absorb(k.buf)
		k.buf = nil
	}

	for len(b) >= k.blockSize {
		k.absorb(b[:k.blockSize])
		b = b[k.blockSize:]
	}

	k.buf = b

	return n, nil
}

func (k0 *keccak) Sum(b []byte) []byte {
	k := *k0
	k.final()
	return k.squeeze(b)
}

func (k *keccak) Reset() {
	for i := range k.S {
		k.S[i] = 0
	}
	k.buf = nil
}

func (k *keccak) Size() int {
	return k.size
}

func (k *keccak) BlockSize() int {
	return k.blockSize
}

func (k *keccak) absorb(block []byte) {
	if len(block) != k.blockSize {
		panic("absorb() called with invalid block size")
	}

	for i := 0; i < k.blockSize/8; i++ {
		k.S[i] ^= uint64le(block[i*8:])
	}
	keccakf(&k.S)
}

func (k *keccak) pad(block []byte) []byte {

	padded := make([]byte, k.blockSize)

	copy(padded, k.buf)
	padded[len(k.buf)] = k.domain
	padded[len(padded)-1] |= 0x80

	return padded
}

func (k *keccak) final() {
	last := k.pad(k.buf)
	k.absorb(last)
}

func (k *keccak) squeeze(b []byte) []byte {
	buf := make([]byte, 8*len(k.S))
	n := k.size
	for {
		for i := range k.S {
			putUint64le(buf[i*8:], k.S[i])
		}
		if n <= k.blockSize {
			b = append(b, buf[:n]...)
			break
		}
		b = append(b, buf[:k.blockSize]...)
		n -= k.blockSize
		keccakf(&k.S)
	}
	return b
}

func keccakf(S *[25]uint64) {
	var bc [5]uint64
	for r := 0; r < rounds; r++ {
		// theta
		for i := range bc {
			bc[i] = S[i] ^ S[5+i] ^ S[10+i] ^ S[15+i] ^ S[20+i]
		}
		for i := range bc {
			t := bc[(i+4)%5] ^ rotl64(bc[(i+1)%5], 1)
			for j := 0; j < len(S); j += 5 {
				S[i+j] ^= t
			}
		}

		// rho phi
		temp := S[1]
		for i := range piLane {
			j := piLane[i]
			temp2 := S[j]
			S[j] = rotl64(temp, rotationConstants[i])
			temp = temp2
		}

		// chi
		for j := 0; j < len(S); j += 5 {
			for i := range bc {
				bc[i] = S[j+i]
			}
			for i := range bc {
				S[j+i] ^= (^bc[(i+1)%5]) & bc[(i+2)%5]
			}
		}

		// iota
		S[0] ^= roundConstants[r]
	}
}

func rotl64(x uint64, n uint) uint64 {
	return (x << n) | (x >> (64 - n))
}

func uint64le(v []byte) uint64 {
	return uint64(v[0]) |
		uint64(v[1])<<8 |
		uint64(v[2])<<16 |
		uint64(v[3])<<24 |
		uint64(v[4])<<32 |
		uint64(v[5])<<40 |
		uint64(v[6])<<48 |
		uint64(v[7])<<56

}

func putUint64le(v []byte, x uint64) {
	v[0] = byte(x)
	v[1] = byte(x >> 8)
	v[2] = byte(x >> 16)
	v[3] = byte(x >> 24)
	v[4] = byte(x >> 32)
	v[5] = byte(x >> 40)
	v[6] = byte(x >> 48)
	v[7] = byte(x >> 56)
}
