package parser

import "time"

// JWTToken represents a parsed JWT token
type JWTToken struct {
	Raw       string
	Header    Header
	Payload   Payload
	Signature string
	Valid     bool
}

// Header represents the JWT header
type Header struct {
	Alg string                 `json:"alg"`
	Typ string                 `json:"typ"`
	Kid string                 `json:"kid,omitempty"`
	Raw map[string]interface{} `json:"-"`
}

// Payload represents the JWT payload/claims
type Payload struct {
	// Standard claims
	Iss string `json:"iss,omitempty"` // Issuer
	Sub string `json:"sub,omitempty"` // Subject
	Aud string `json:"aud,omitempty"` // Audience
	Exp int64  `json:"exp,omitempty"` // Expiration
	Nbf int64  `json:"nbf,omitempty"` // Not Before
	Iat int64  `json:"iat,omitempty"` // Issued At
	Jti string `json:"jti,omitempty"` // JWT ID

	// Custom claims stored as map
	Raw map[string]interface{} `json:"-"`
}

// HasExpiration returns true if the token has an expiration claim
func (p *Payload) HasExpiration() bool {
	return p.Exp > 0
}

// IsExpired checks if the token is expired
func (p *Payload) IsExpired() bool {
	if !p.HasExpiration() {
		return false
	}
	return time.Now().Unix() > p.Exp
}

// ExpiresIn returns the duration until expiration
func (p *Payload) ExpiresIn() time.Duration {
	if !p.HasExpiration() {
		return 0
	}
	return time.Until(time.Unix(p.Exp, 0))
}

// ExpirationYears returns how many years until expiration
func (p *Payload) ExpirationYears() float64 {
	if !p.HasExpiration() {
		return 0
	}
	return p.ExpiresIn().Hours() / 24 / 365
}
