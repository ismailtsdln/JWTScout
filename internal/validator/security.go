package validator

import (
	"strings"

	"github.com/ismailtasdelen/JWTScout/internal/parser"
)

// Validator performs security validation on JWT tokens
type Validator struct {
	findings []*Finding
}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	return &Validator{
		findings: make([]*Finding, 0),
	}
}

// Validate performs comprehensive security validation on a JWT token
func (v *Validator) Validate(token *parser.JWTToken) []*Finding {
	v.findings = make([]*Finding, 0)

	v.checkAlgorithm(token)
	v.checkExpiration(token)
	v.checkClaims(token)
	v.checkKid(token)

	return v.findings
}

// checkAlgorithm validates the signing algorithm
func (v *Validator) checkAlgorithm(token *parser.JWTToken) {
	alg := strings.ToLower(token.Header.Alg)

	// Check for alg:none
	if alg == "none" {
		v.addFinding(FindingTemplateAlgNone(
			"This token can be modified and replayed without signature verification",
		))
		return
	}

	// Check for weak/deprecated algorithms
	weakAlgorithms := []string{"hs256", "hs384", "hs512", "rs256"}
	for _, weak := range weakAlgorithms {
		if alg == weak {
			// HS* algorithms are potentially vulnerable to brute force
			if strings.HasPrefix(alg, "hs") {
				v.addFinding(NewFinding(
					FindingWeakAlgorithm,
					SeverityWarning,
					"HMAC Algorithm Detected",
					"HMAC algorithms may be vulnerable to brute force attacks if weak secrets are used",
					"Algorithm: "+token.Header.Alg,
				))
			}
			break
		}
	}

	// Check for RS256 (potential algorithm confusion)
	if alg == "rs256" {
		v.addFinding(NewFinding(
			FindingAlgConfusion,
			SeverityWarning,
			"RS256 Algorithm Confusion Risk",
			"RS256 tokens may be vulnerable to algorithm confusion attacks (RS256→HS256)",
			"Attackers may attempt to switch the algorithm to HS256 and sign with the public key",
		))
	}
}

// checkExpiration validates expiration claims
func (v *Validator) checkExpiration(token *parser.JWTToken) {
	// Check if expiration exists
	if !token.Payload.HasExpiration() {
		v.addFinding(FindingTemplateNoExpiration())
		return
	}

	// Check if already expired
	if token.Payload.IsExpired() {
		v.addFinding(FindingTemplateExpired(
			token.Payload.ExpiresIn().String() + " ago",
		))
		return
	}

	// Check for excessively long expiration (>1 year)
	years := token.Payload.ExpirationYears()
	if years > 1.0 {
		v.addFinding(FindingTemplateLongExpiration(years))
	}
}

// checkClaims validates standard claims
func (v *Validator) checkClaims(token *parser.JWTToken) {
	missingClaims := []string{}

	// Check for important claims
	if token.Payload.Iss == "" {
		missingClaims = append(missingClaims, "iss (issuer)")
	}
	if token.Payload.Sub == "" {
		missingClaims = append(missingClaims, "sub (subject)")
	}
	if token.Payload.Iat == 0 {
		missingClaims = append(missingClaims, "iat (issued at)")
	}

	if len(missingClaims) > 0 {
		v.addFinding(NewFinding(
			FindingMissingClaims,
			SeverityInfo,
			"Missing Standard Claims",
			"Some standard JWT claims are not present",
			"Missing: "+strings.Join(missingClaims, ", "),
		))
	}

	// Check for suspicious claim values
	v.checkSuspiciousClaims(token)
}

// checkSuspiciousClaims looks for potentially dangerous claim values
func (v *Validator) checkSuspiciousClaims(token *parser.JWTToken) {
	suspicious := []string{}

	for key, value := range token.Payload.Raw {
		strVal, ok := value.(string)
		if !ok {
			continue
		}

		// Check for common privilege escalation patterns
		lowerKey := strings.ToLower(key)
		lowerVal := strings.ToLower(strVal)

		if (lowerKey == "role" || lowerKey == "admin" || lowerKey == "privilege") &&
			(lowerVal == "admin" || lowerVal == "administrator" || lowerVal == "root") {
			suspicious = append(suspicious, key+"="+strVal)
		}
	}

	if len(suspicious) > 0 {
		v.addFinding(NewFinding(
			FindingSuspiciousClaims,
			SeverityInfo,
			"Privileged Claims Detected",
			"The token contains claims with elevated privileges",
			"Claims: "+strings.Join(suspicious, ", "),
		))
	}
}

// checkKid validates the kid (Key ID) header
func (v *Validator) checkKid(token *parser.JWTToken) {
	kid := token.Header.Kid
	if kid == "" {
		return
	}

	// Check for path traversal
	if strings.Contains(kid, "..") || strings.Contains(kid, "/") || strings.Contains(kid, "\\") {
		v.addFinding(FindingTemplateSuspiciousKid(
			kid,
			"Contains path traversal characters",
		))
	}

	// Check for URL-based kid
	if strings.HasPrefix(kid, "http://") || strings.HasPrefix(kid, "https://") {
		v.addFinding(FindingTemplateSuspiciousKid(
			kid,
			"Contains URL reference",
		))
	}

	// Check for SQL injection patterns
	sqlPatterns := []string{"'", "\"", "--", ";", "/*", "*/"}
	for _, pattern := range sqlPatterns {
		if strings.Contains(kid, pattern) {
			v.addFinding(FindingTemplateSuspiciousKid(
				kid,
				"Contains potential SQL injection characters",
			))
			break
		}
	}

	// Check for null/empty kid
	if strings.TrimSpace(kid) == "" || kid == "null" || kid == "NULL" {
		v.addFinding(FindingTemplateSuspiciousKid(
			kid,
			"Empty or null kid value",
		))
	}
}

// addFinding adds a finding to the validator's results
func (v *Validator) addFinding(finding *Finding) {
	v.findings = append(v.findings, finding)
}

// GetFindings returns all findings
func (v *Validator) GetFindings() []*Finding {
	return v.findings
}

// HasCriticalFindings returns true if any critical findings exist
func (v *Validator) HasCriticalFindings() bool {
	for _, f := range v.findings {
		if f.Severity == SeverityCritical {
			return true
		}
	}
	return false
}
