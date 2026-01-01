package validator

import "fmt"

// Severity levels for findings
type Severity int

const (
	// SeverityInfo indicates informational findings
	SeverityInfo Severity = iota
	// SeverityWarning indicates potential security issues
	SeverityWarning
	// SeverityCritical indicates critical vulnerabilities
	SeverityCritical
)

// String returns the string representation of severity
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// FindingType represents the type of security finding
type FindingType string

const (
	// Algorithm-related findings
	FindingAlgNone          FindingType = "ALG_NONE"
	FindingWeakAlgorithm    FindingType = "WEAK_ALGORITHM"
	FindingAlgConfusion     FindingType = "ALG_CONFUSION_RISK"
	
	// Expiration-related findings
	FindingNoExpiration     FindingType = "NO_EXPIRATION"
	FindingExpired          FindingType = "EXPIRED"
	FindingLongExpiration   FindingType = "LONG_EXPIRATION"
	
	// Claim-related findings
	FindingMissingClaims    FindingType = "MISSING_CLAIMS"
	FindingSuspiciousClaims FindingType = "SUSPICIOUS_CLAIMS"
	
	// Header-related findings
	FindingSuspiciousKid    FindingType = "SUSPICIOUS_KID"
	FindingMissingTyp       FindingType = "MISSING_TYP"
)

// Finding represents a security finding
type Finding struct {
	Type        FindingType
	Severity    Severity
	Title       string
	Description string
	Details     string
}

// NewFinding creates a new finding
func NewFinding(ftype FindingType, severity Severity, title, description, details string) *Finding {
	return &Finding{
		Type:        ftype,
		Severity:    severity,
		Title:       title,
		Description: description,
		Details:     details,
	}
}

// Common finding templates
var (
	FindingTemplateAlgNone = func(details string) *Finding {
		return NewFinding(
			FindingAlgNone,
			SeverityCritical,
			"Algorithm: none Detected",
			"The token uses 'alg: none' which means it has no signature verification",
			details,
		)
	}

	FindingTemplateNoExpiration = func() *Finding {
		return NewFinding(
			FindingNoExpiration,
			SeverityWarning,
			"No Expiration Set",
			"The token does not have an expiration claim (exp), making it valid forever",
			"Tokens without expiration can be reused indefinitely if compromised",
		)
	}

	FindingTemplateExpired = func(details string) *Finding {
		return NewFinding(
			FindingExpired,
			SeverityInfo,
			"Token Expired",
			"The token has already expired and should not be accepted",
			details,
		)
	}

	FindingTemplateLongExpiration = func(years float64) *Finding {
		return NewFinding(
			FindingLongExpiration,
			SeverityWarning,
			"Excessively Long Expiration",
			"The token has an unusually long expiration period",
			fmt.Sprintf("Token expires in %.1f years. Long-lived tokens increase security risk.", years),
		)
	}

	FindingTemplateWeakAlgorithm = func(alg string) *Finding {
		return NewFinding(
			FindingWeakAlgorithm,
			SeverityWarning,
			"Weak/Deprecated Algorithm",
			"The token uses a weak or deprecated signing algorithm",
			fmt.Sprintf("Algorithm '%s' may not be suitable for production use", alg),
		)
	}

	FindingTemplateSuspiciousKid = func(kid, reason string) *Finding {
		return NewFinding(
			FindingSuspiciousKid,
			SeverityWarning,
			"Suspicious 'kid' Header",
			"The 'kid' header contains potentially dangerous content",
			fmt.Sprintf("kid: %s - %s", kid, reason),
		)
	}
)

// Import fmt package for sprintf
import "fmt"
