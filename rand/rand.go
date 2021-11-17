package rand

import (
	crand "crypto/rand"
	"math/big"
)

const runes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// Generate creates a controlled cryptographic string
// Panics on error
func Generate(n int) string {
	letters := []rune(runes)
	b := make([]rune, n)
	for i := range b {
		v, err := crand.Int(crand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err)
		}
		b[i] = letters[v.Int64()]
	}
	return string(b)
}

