package rand

import (
    "crypto/rand"
    "encoding/hex"
    "math/big"
)

/// Rand

const RandLength = 32

type Rand [RandLength]byte

// Constructors
// NewRand -- initialize and return a random value
func NewRand() (r Rand) {
    b := make([]byte, RandLength)
    rand.Read(b)
    return RandFromBytes(b)
}

// RandFromBytes -- convert one or more byte arrays to a fixed length randomness through hashing
func RandFromBytes(b ...[]byte) (r Rand) {
    HashBytes(b...).Sum(r[:0])
    return
}

// RandFromHex -- convert one or more hex strings to a fixed length randomness through hashing
func RandFromHex(s ...string) (r Rand) {
    return RandFromBytes(MapHexToBytes(s)...)
}

// Getters

// Bytes -- Return Rand as []byte
func (r Rand) Bytes() []byte {
    return r[:]
}

// String -- Return Rand as hex string, not prefixed with 0x
func (r Rand) String() string {
    return hex.EncodeToString(r[:])
}

func (r Rand) DerivedRand(x ...[]byte) Rand {
    // Keccak is not susceptible to length-extension-attacks, so we can use it as-is to implement an HMAC
    ri := r
    for _, xi := range x {
        HashBytes(ri.Bytes(),xi).Sum(ri[:0])
    }
    return ri
}


// Ders -- Derive randomness with indices given as strings
func (r Rand) Ders(s ...string) Rand {
    return r.DerivedRand(MapStringToBytes(s)...)
}

// Deri -- Derive randomness with indices given as ints
func (r Rand) Deri(vi ...int) Rand {
    return r.Ders(MapItoa(vi)...)
}

func (r Rand) Modulo(n int) int {
    //var b big.Int
    b := big.NewInt(0)
    b.SetBytes(r.Bytes())
    b.Mod(b, big.NewInt(int64(n)))
    return int(b.Int64())
}

func (r Rand) RandomPerm(n int, k int) []int {
    l := make([]int, n)
    for i := range l {
        l[i] = i
    }
    for i := 0; i < k; i++ {
        j := r.Deri(i).Modulo(n-i) + i
        l[i], l[j] = l[j], l[i]
    }
    return l[:k]
}