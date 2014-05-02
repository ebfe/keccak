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
	var tmp uint64

	for r := 0; r < rounds; r++ {
		// theta
		bc[0] = S[0] ^ S[5] ^ S[10] ^ S[15] ^ S[20]
		bc[1] = S[1] ^ S[6] ^ S[11] ^ S[16] ^ S[21]
		bc[2] = S[2] ^ S[7] ^ S[12] ^ S[17] ^ S[22]
		bc[3] = S[3] ^ S[8] ^ S[13] ^ S[18] ^ S[23]
		bc[4] = S[4] ^ S[9] ^ S[14] ^ S[19] ^ S[24]
		tmp = bc[4] ^ (bc[1]<<1 | bc[1]>>(64-1))
		S[0] ^= tmp
		S[5] ^= tmp
		S[10] ^= tmp
		S[15] ^= tmp
		S[20] ^= tmp
		tmp = bc[0] ^(bc[2]<<1 | bc[2]>>(64-1))
		S[1] ^= tmp
		S[6] ^= tmp
		S[11] ^= tmp
		S[16] ^= tmp
		S[21] ^= tmp
		tmp = bc[1] ^ (bc[3]<<1 | bc[3]>>(64-1))
		S[2] ^= tmp
		S[7] ^= tmp
		S[12] ^= tmp
		S[17] ^= tmp
		S[22] ^= tmp
		tmp = bc[2] ^  (bc[4]<<1 | bc[4]>>(64-1))
		S[3] ^= tmp
		S[8] ^= tmp
		S[13] ^= tmp
		S[18] ^= tmp
		S[23] ^= tmp
		tmp = bc[3] ^ (bc[0]<<1 | bc[0]>>(64-1))
		S[4] ^= tmp
		S[9] ^= tmp
		S[14] ^= tmp
		S[19] ^= tmp
		S[24] ^= tmp

		// rho phi
		tmp = S[1]
		tmp, S[10] = S[10], tmp << 1 | tmp >> (64- 1)
		tmp, S[7] = S[7],   tmp << 3 | tmp >> (64- 3)
		tmp, S[11] = S[11], tmp << 6 | tmp >> (64- 6)
		tmp, S[17] = S[17], tmp << 10 | tmp >> (64- 10)
		tmp, S[18] = S[18], tmp << 15 | tmp >> (64- 15)
		tmp, S[3] = S[3],   tmp << 21 | tmp >> (64- 21)
		tmp, S[5] = S[5],   tmp << 28 | tmp >> (64- 28)
		tmp, S[16] = S[16], tmp << 36 | tmp >> (64- 36)
		tmp, S[8] = S[8],   tmp << 45 | tmp >> (64- 45)
		tmp, S[21] = S[21], tmp << 55 | tmp >> (64- 55)
		tmp, S[24] = S[24], tmp << 2 | tmp >> (64- 2)
		tmp, S[4] = S[4],   tmp << 14 | tmp >> (64- 14)
		tmp, S[15] = S[15], tmp << 27 | tmp >> (64- 27)
		tmp, S[23] = S[23], tmp << 41 | tmp >> (64- 41)
		tmp, S[19] = S[19], tmp << 56 | tmp >> (64- 56)
		tmp, S[13] = S[13], tmp << 8 | tmp >> (64- 8)
		tmp, S[12] = S[12], tmp << 25 | tmp >> (64- 25)
		tmp, S[2] = S[2],   tmp << 43 | tmp >> (64- 43)
		tmp, S[20] = S[20], tmp << 62 | tmp >> (64- 62)
		tmp, S[14] = S[14], tmp << 18 | tmp >> (64- 18)
		tmp, S[22] = S[22], tmp << 39 | tmp >> (64- 39)
		tmp, S[9] = S[9],   tmp << 61 | tmp >> (64- 61)
		tmp, S[6] = S[6],   tmp << 20 | tmp >> (64- 20)
		S[1] =              tmp << 44 | tmp >> (64- 44)

		// chi
		bc[0] = S[0]
		bc[1] = S[1]
		bc[2] = S[2]
		bc[3] = S[3]
		bc[4] = S[4]
		S[0] ^= (^bc[1]) & bc[2]
		S[1] ^= (^bc[2]) & bc[3]
		S[2] ^= (^bc[3]) & bc[4]
		S[3] ^= (^bc[4]) & bc[0]
		S[4] ^= (^bc[0]) & bc[1]
		bc[0] = S[5]
		bc[1] = S[6]
		bc[2] = S[7]
		bc[3] = S[8]
		bc[4] = S[9]
		S[5] ^= (^bc[1]) & bc[2]
		S[6] ^= (^bc[2]) & bc[3]
		S[7] ^= (^bc[3]) & bc[4]
		S[8] ^= (^bc[4]) & bc[0]
		S[9] ^= (^bc[0]) & bc[1]
		bc[0] = S[10]
		bc[1] = S[11]
		bc[2] = S[12]
		bc[3] = S[13]
		bc[4] = S[14]
		S[10] ^= (^bc[1]) & bc[2]
		S[11] ^= (^bc[2]) & bc[3]
		S[12] ^= (^bc[3]) & bc[4]
		S[13] ^= (^bc[4]) & bc[0]
		S[14] ^= (^bc[0]) & bc[1]
		bc[0] = S[15]
		bc[1] = S[16]
		bc[2] = S[17]
		bc[3] = S[18]
		bc[4] = S[19]
		S[15] ^= (^bc[1]) & bc[2]
		S[16] ^= (^bc[2]) & bc[3]
		S[17] ^= (^bc[3]) & bc[4]
		S[18] ^= (^bc[4]) & bc[0]
		S[19] ^= (^bc[0]) & bc[1]
		bc[0] = S[20]
		bc[1] = S[21]
		bc[2] = S[22]
		bc[3] = S[23]
		bc[4] = S[24]
		S[20] ^= (^bc[1]) & bc[2]
		S[21] ^= (^bc[2]) & bc[3]
		S[22] ^= (^bc[3]) & bc[4]
		S[23] ^= (^bc[4]) & bc[0]
		S[24] ^= (^bc[0]) & bc[1]

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
