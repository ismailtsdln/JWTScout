package parser

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidFormat is returned when the JWT format is invalid
	ErrInvalidFormat = errors.New("invalid JWT format: expected 3 parts separated by dots")
	// ErrInvalidEncoding is returned when base64 decoding fails
	ErrInvalidEncoding = errors.New("invalid base64 encoding")
	// ErrInvalidJSON is returned when JSON parsing fails
	ErrInvalidJSON = errors.New("invalid JSON in header or payload")
)

// ParseJWT parses a JWT token string and extracts its components
func ParseJWT(tokenString string) (*JWTToken, error) {
	tokenString = strings.TrimSpace(tokenString)

	// Split the token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidFormat
	}

	token := &JWTToken{
		Raw: tokenString,
	}

	// Decode header
	header, err := DecodeHeader(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}
	token.Header = *header

	// Decode payload
	payload, err := DecodePayload(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}
	token.Payload = *payload

	// Extract signature (keep it base64 encoded)
	token.Signature = parts[2]

	return token, nil
}

// DecodeHeader decodes the JWT header from base64url
func DecodeHeader(headerB64 string) (*Header, error) {
	data, err := base64URLDecode(headerB64)
	if err != nil {
		return nil, err
	}

	var rawHeader map[string]interface{}
	if err := json.Unmarshal(data, &rawHeader); err != nil {
		return nil, ErrInvalidJSON
	}

	header := &Header{
		Raw: rawHeader,
	}

	// Extract standard fields
	if alg, ok := rawHeader["alg"].(string); ok {
		header.Alg = alg
	}
	if typ, ok := rawHeader["typ"].(string); ok {
		header.Typ = typ
	}
	if kid, ok := rawHeader["kid"].(string); ok {
		header.Kid = kid
	}

	return header, nil
}

// DecodePayload decodes the JWT payload from base64url
func DecodePayload(payloadB64 string) (*Payload, error) {
	data, err := base64URLDecode(payloadB64)
	if err != nil {
		return nil, err
	}

	var rawPayload map[string]interface{}
	if err := json.Unmarshal(data, &rawPayload); err != nil {
		return nil, ErrInvalidJSON
	}

	payload := &Payload{
		Raw: rawPayload,
	}

	// Extract standard claims
	if iss, ok := rawPayload["iss"].(string); ok {
		payload.Iss = iss
	}
	if sub, ok := rawPayload["sub"].(string); ok {
		payload.Sub = sub
	}
	if aud, ok := rawPayload["aud"].(string); ok {
		payload.Aud = aud
	}
	if jti, ok := rawPayload["jti"].(string); ok {
		payload.Jti = jti
	}

	// Extract numeric claims (exp, nbf, iat)
	if exp, ok := rawPayload["exp"].(float64); ok {
		payload.Exp = int64(exp)
	}
	if nbf, ok := rawPayload["nbf"].(float64); ok {
		payload.Nbf = int64(nbf)
	}
	if iat, ok := rawPayload["iat"].(float64); ok {
		payload.Iat = int64(iat)
	}

	return payload, nil
}

// base64URLDecode decodes a base64url-encoded string
// JWT uses base64url encoding (RFC 4648) which is different from standard base64
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if necessary
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	// Replace URL-safe characters with standard base64 characters
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrInvalidEncoding
	}

	return data, nil
}

// base64URLEncode encodes data to base64url format
func base64URLEncode(data []byte) string {
	s := base64.StdEncoding.EncodeToString(data)

	// Remove padding
	s = strings.TrimRight(s, "=")

	// Replace standard base64 characters with URL-safe characters
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")

	return s
}

// Base64URLEncode is exported for use in other packages
func Base64URLEncode(data []byte) string {
	return base64URLEncode(data)
}
