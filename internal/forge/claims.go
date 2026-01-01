package forge

import (
	"strings"
	"time"

	"github.com/ismailtasdelen/JWTScout/internal/parser"
)

// Forger handles token modification
type Forger struct {
	OriginalToken *parser.JWTToken
	Payload       map[string]interface{}
	Header        map[string]interface{}
}

// NewForger creates a new forger instance
func NewForger(token *parser.JWTToken) *Forger {
	// Deep copy payload and header maps
	newPayload := make(map[string]interface{})
	for k, v := range token.Payload.Raw {
		newPayload[k] = v
	}

	newHeader := make(map[string]interface{})
	for k, v := range token.Header.Raw {
		newHeader[k] = v
	}

	return &Forger{
		OriginalToken: token,
		Payload:       newPayload,
		Header:        newHeader,
	}
}

// SetClaim sets or overrides a claim in the payload
func (f *Forger) SetClaim(key string, value interface{}) {
	f.Payload[key] = value
}

// RemoveClaim removes a claim from the payload
func (f *Forger) RemoveClaim(key string) {
	delete(f.Payload, key)
}

// SetHeader sets or overrides a header field
func (f *Forger) SetHeader(key string, value interface{}) {
	f.Header[key] = value
}

// ExtendExpiration extends the expiration of the token
func (f *Forger) ExtendExpiration(duration time.Duration) {
	newExp := time.Now().Add(duration).Unix()
	f.Payload["exp"] = float64(newExp)
}

// SetAdminRole attempts common admin privilege escalation
func (f *Forger) SetAdminRole() {
	f.Payload["role"] = "admin"
	f.Payload["admin"] = true
	f.Payload["root"] = true
}

// ParseClaimString parses a "key=value" string and adds it to payload
func (f *Forger) ParseClaimString(claimStr string) {
	parts := strings.SplitN(claimStr, "=", 2)
	if len(parts) == 2 {
		f.SetClaim(parts[0], parts[1])
	}
}
