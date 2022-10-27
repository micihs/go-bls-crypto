package rand

import (
    "golang.org/x/crypto/sha3"
    "hash"
)

func HashBytes(b ...[]byte) hash.Hash {
    d := sha3.New256()
    for _, bi := range b {
        d.Write(bi)
    }
    return d
}