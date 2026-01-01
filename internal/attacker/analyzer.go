package attacker

import (
	"github.com/ismailtsdln/JWTScout/internal/parser"
	"github.com/ismailtsdln/JWTScout/internal/validator"
)

// Analyzer performs comprehensive token analysis
type Analyzer struct {
	validator *validator.Validator
}

// NewAnalyzer creates a new analyzer instance
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		validator: validator.NewValidator(),
	}
}

// Analyze performs comprehensive security analysis on a JWT token
func (a *Analyzer) Analyze(token *parser.JWTToken) []*validator.Finding {
	return a.validator.Validate(token)
}
