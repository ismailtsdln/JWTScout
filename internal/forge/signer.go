package forge

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash"
	"strings"

	"github.com/ismailtsdln/JWTScout/internal/parser"
)

// Signer handles re-signing modified tokens
type Signer struct {
	Forger *Forger
}

// NewSigner creates a new signer
func NewSigner(forger *Forger) *Signer {
	return &Signer{
		Forger: forger,
	}
}

// GenerateUnsigned creates a token with no signature (alg: none)
func (s *Signer) GenerateUnsigned() (string, error) {
	s.Forger.SetHeader("alg", "none")

	headerB64, payloadB64, err := s.encodeParts()
	if err != nil {
		return "", err
	}

	// Unsigned token (ends with dot)
	return fmt.Sprintf("%s.%s.", headerB64, payloadB64), nil
}

// GenerateHMAC signs the token using an HMAC secret (HS256/384/512)
func (s *Signer) GenerateHMAC(secret string, alg string) (string, error) {
	alg = strings.ToUpper(alg)
	if !strings.HasPrefix(alg, "HS") {
		return "", fmt.Errorf("only HS algorithms supported for HMAC signing")
	}

	s.Forger.SetHeader("alg", alg)

	headerB64, payloadB64, err := s.encodeParts()
	if err != nil {
		return "", err
	}

	signingInput := fmt.Sprintf("%s.%s", headerB64, payloadB64)

	var h hash.Hash
	switch alg {
	case "HS256":
		h = hmac.New(sha256.New, []byte(secret))
	case "HS384":
		h = hmac.New(sha512.New384, []byte(secret))
	case "HS512":
		h = hmac.New(sha512.New, []byte(secret))
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}

	h.Write([]byte(signingInput))
	sigBytes := h.Sum(nil)
	sigB64 := parser.Base64URLEncode(sigBytes)

	return fmt.Sprintf("%s.%s", signingInput, sigB64), nil
}

// encodeParts helper to JSON encode and Base64URL encode header and payload
func (s *Signer) encodeParts() (string, string, error) {
	headerJSON, err := json.Marshal(s.Forger.Header)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode header: %w", err)
	}

	payloadJSON, err := json.Marshal(s.Forger.Payload)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode payload: %w", err)
	}

	headerB64 := parser.Base64URLEncode(headerJSON)
	payloadB64 := parser.Base64URLEncode(payloadJSON)

	return headerB64, payloadB64, nil
}
