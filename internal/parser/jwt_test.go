package parser

import (
	"encoding/json"
	"testing"
)

func TestParseJWT(t *testing.T) {
	// Simple JWT: {"alg":"HS256","typ":"JWT"}.{"sub":"1234567890","name":"John Doe","iat":1516239022}.signature
	header := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
	payload := map[string]interface{}{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}

	headerB64 := Base64URLEncode(mustMarshal(header))
	payloadB64 := Base64URLEncode(mustMarshal(payload))
	tokenStr := headerB64 + "." + payloadB64 + ".fake-signature"

	token, err := ParseJWT(tokenStr)
	if err != nil {
		t.Fatalf("ParseJWT failed: %v", err)
	}

	if token.Header.Alg != "HS256" {
		t.Errorf("expected alg HS256, got %s", token.Header.Alg)
	}

	if token.Payload.Sub != "1234567890" {
		t.Errorf("expected sub 1234567890, got %s", token.Payload.Sub)
	}
}

func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestBase64URL(t *testing.T) {
	data := []byte("hello world?")
	encoded := Base64URLEncode(data)
	decoded, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if string(decoded) != string(data) {
		t.Errorf("expected %s, got %s", string(data), string(decoded))
	}
}
