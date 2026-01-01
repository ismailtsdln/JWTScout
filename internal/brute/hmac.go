package brute

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"
	"sync"

	"github.com/ismailtsdln/JWTScout/internal/parser"
)

// BruteForcer performs HMAC secret brute forcing
type BruteForcer struct {
	token      *parser.JWTToken
	algorithm  string
	numWorkers int
}

// NewBruteForcer creates a new brute forcer
func NewBruteForcer(token *parser.JWTToken, numWorkers int) (*BruteForcer, error) {
	alg := strings.ToUpper(token.Header.Alg)

	// Only support HMAC algorithms
	if !strings.HasPrefix(alg, "HS") {
		return nil, fmt.Errorf("brute force only works with HMAC algorithms (HS256, HS384, HS512), got: %s", alg)
	}

	if numWorkers <= 0 {
		numWorkers = 4 // default worker count
	}

	return &BruteForcer{
		token:      token,
		algorithm:  alg,
		numWorkers: numWorkers,
	}, nil
}

// BruteForce attempts to find the secret using a wordlist
func (bf *BruteForcer) BruteForce(wordlist []string) (string, bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Get the signing input (header.payload)
	parts := strings.Split(bf.token.Raw, ".")
	if len(parts) != 3 {
		return "", false
	}
	signingInput := parts[0] + "." + parts[1]

	// Get expected signature
	expectedSig := parts[2]

	// Channel for secrets to test
	secrets := make(chan string, 100)

	// Channel for results
	type result struct {
		secret string
		found  bool
	}
	results := make(chan result) // unbuffered, we only need one

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < bf.numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case secret, ok := <-secrets:
					if !ok {
						return
					}
					if bf.verifySignature(signingInput, expectedSig, secret) {
						select {
						case results <- result{secret: secret, found: true}:
							cancel() // stop others
						case <-ctx.Done():
						}
						return
					}
				}
			}
		}()
	}

	// Feed wordlist to workers
	go func() {
		defer close(secrets)
		for _, word := range wordlist {
			select {
			case <-ctx.Done():
				return
			case secrets <- word:
			}
		}
	}()

	// Wait for workers in separate goroutine
	go func() {
		wg.Wait()
		close(results)
	}()

	// Check results
	for res := range results {
		if res.found {
			return res.secret, true
		}
	}

	return "", false
}

// verifySignature checks if a secret produces the expected signature
func (bf *BruteForcer) verifySignature(signingInput, expectedSig, secret string) bool {
	// Create HMAC based on algorithm
	var h hash.Hash
	switch bf.algorithm {
	case "HS256":
		h = hmac.New(sha256.New, []byte(secret))
	case "HS384":
		h = hmac.New(sha512.New384, []byte(secret))
	case "HS512":
		h = hmac.New(sha512.New, []byte(secret))
	default:
		return false
	}

	// Sign the input
	h.Write([]byte(signingInput))
	signature := h.Sum(nil)

	// Encode to base64url
	actualSig := parser.Base64URLEncode(signature)

	// Use hmac.Equal for constant-time comparison
	return hmac.Equal([]byte(actualSig), []byte(expectedSig))
}
