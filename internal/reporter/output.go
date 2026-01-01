package reporter

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/ismailtsdln/JWTScout/internal/parser"
	"github.com/ismailtsdln/JWTScout/internal/validator"
)

// Reporter handles formatted output for JWTScout
type Reporter struct {
	verbose bool
}

// NewReporter creates a new reporter instance
func NewReporter(verbose bool) *Reporter {
	return &Reporter{
		verbose: verbose,
	}
}

// PrintBanner prints the JWTScout banner
func (r *Reporter) PrintBanner() {
	banner := `
   ___          _________ _____                 _   
  |_  |        |_   _/  ___/  __ \               | |  
    | |_      __ | | \ '--.| /  \/ ___  _   _ ___| |_ 
    | \ \ /\ / / | |  '--. \ |    / _ \| | | / __| __|
/\__/ /\ V  V /  | | /\__/ / \__/\ (_) | |_| \__ \ |_ 
\____/  \_/\_/   \_/ \____/ \____/\___/ \__,_|___/\__|
                                                      
         JWT Security Testing Tool v1.0
         github.com/ismailtsdln/JWTScout
`
	color.Cyan(banner)
	fmt.Println()
}

// PrintTokenInfo displays decoded token information
func (r *Reporter) PrintTokenInfo(token *parser.JWTToken) {
	color.New(color.Bold, color.FgWhite).Println("📋 Token Information")
	fmt.Println(strings.Repeat("─", 60))

	// Header
	color.Yellow("\n🔖 Header:")
	fmt.Printf("  Algorithm: %s\n", r.formatValue(token.Header.Alg))
	fmt.Printf("  Type:      %s\n", r.formatValue(token.Header.Typ))
	if token.Header.Kid != "" {
		fmt.Printf("  Key ID:    %s\n", r.formatValue(token.Header.Kid))
	}

	// Print other header fields if verbose
	if r.verbose && len(token.Header.Raw) > 0 {
		fmt.Println("\n  Additional Header Fields:")
		for k, v := range token.Header.Raw {
			if k != "alg" && k != "typ" && k != "kid" {
				fmt.Printf("    %s: %v\n", k, v)
			}
		}
	}

	// Payload
	color.Yellow("\n📦 Payload:")
	if token.Payload.Iss != "" {
		fmt.Printf("  Issuer:    %s\n", token.Payload.Iss)
	}
	if token.Payload.Sub != "" {
		fmt.Printf("  Subject:   %s\n", token.Payload.Sub)
	}
	if token.Payload.Aud != "" {
		fmt.Printf("  Audience:  %s\n", token.Payload.Aud)
	}
	if token.Payload.Jti != "" {
		fmt.Printf("  JWT ID:    %s\n", token.Payload.Jti)
	}

	// Time-based claims
	if token.Payload.Iat > 0 {
		iat := time.Unix(token.Payload.Iat, 0)
		fmt.Printf("  Issued At: %s (%s ago)\n",
			iat.Format(time.RFC3339),
			time.Since(iat).Round(time.Second))
	}
	if token.Payload.Nbf > 0 {
		nbf := time.Unix(token.Payload.Nbf, 0)
		fmt.Printf("  Not Before: %s\n", nbf.Format(time.RFC3339))
	}
	if token.Payload.Exp > 0 {
		exp := time.Unix(token.Payload.Exp, 0)
		remaining := time.Until(exp)
		if remaining > 0 {
			fmt.Printf("  Expires:   %s (in %s)\n",
				exp.Format(time.RFC3339),
				remaining.Round(time.Second))
		} else {
			fmt.Printf("  Expires:   %s (expired %s ago)\n",
				exp.Format(time.RFC3339),
				(-remaining).Round(time.Second))
		}
	}

	// Print other payload fields if verbose
	if r.verbose && len(token.Payload.Raw) > 0 {
		fmt.Println("\n  Additional Claims:")
		standardClaims := map[string]bool{
			"iss": true, "sub": true, "aud": true,
			"exp": true, "nbf": true, "iat": true, "jti": true,
		}
		for k, v := range token.Payload.Raw {
			if !standardClaims[k] {
				fmt.Printf("    %s: %v\n", k, v)
			}
		}
	}

	// Signature
	color.Yellow("\n🔐 Signature:")
	sigPreview := token.Signature
	if len(sigPreview) > 40 {
		sigPreview = sigPreview[:40] + "..."
	}
	fmt.Printf("  %s\n", sigPreview)

	fmt.Println()
}

// PrintFindings displays security findings
func (r *Reporter) PrintFindings(findings []*validator.Finding) {
	if len(findings) == 0 {
		r.PrintSuccess("No security issues detected! ✓")
		return
	}

	color.New(color.Bold, color.FgWhite).Println("🔍 Security Analysis Results")
	fmt.Println(strings.Repeat("─", 60))

	// Group by severity
	critical := []*validator.Finding{}
	warnings := []*validator.Finding{}
	info := []*validator.Finding{}

	for _, f := range findings {
		switch f.Severity {
		case validator.SeverityCritical:
			critical = append(critical, f)
		case validator.SeverityWarning:
			warnings = append(warnings, f)
		case validator.SeverityInfo:
			info = append(info, f)
		}
	}

	// Print critical findings
	if len(critical) > 0 {
		fmt.Println()
		for _, f := range critical {
			r.printFinding(f)
		}
	}

	// Print warnings
	if len(warnings) > 0 {
		fmt.Println()
		for _, f := range warnings {
			r.printFinding(f)
		}
	}

	// Print info
	if len(info) > 0 && r.verbose {
		fmt.Println()
		for _, f := range info {
			r.printFinding(f)
		}
	}

	fmt.Println()
}

// printFinding prints a single finding
func (r *Reporter) printFinding(f *validator.Finding) {
	var icon string
	var printer *color.Color

	switch f.Severity {
	case validator.SeverityCritical:
		icon = "🔴"
		printer = color.New(color.FgRed, color.Bold)
	case validator.SeverityWarning:
		icon = "🟡"
		printer = color.New(color.FgYellow, color.Bold)
	case validator.SeverityInfo:
		icon = "🟢"
		printer = color.New(color.FgCyan, color.Bold)
	}

	printer.Printf("%s [%s] %s\n", icon, f.Severity, f.Title)
	fmt.Printf("   %s\n", f.Description)
	if f.Details != "" {
		color.New(color.Faint).Printf("   → %s\n", f.Details)
	}
	fmt.Println()
}

// PrintSuccess prints a success message
func (r *Reporter) PrintSuccess(message string) {
	color.Green("✓ " + message)
}

// PrintWarning prints a warning message
func (r *Reporter) PrintWarning(message string) {
	color.Yellow("⚠ " + message)
}

// PrintError prints an error message
func (r *Reporter) PrintError(message string) {
	color.Red("✗ " + message)
}

// PrintInfo prints an info message
func (r *Reporter) PrintInfo(message string) {
	color.Cyan("ℹ " + message)
}

// PrintSeparator prints a visual separator
func (r *Reporter) PrintSeparator() {
	fmt.Println(strings.Repeat("─", 60))
}

// formatValue formats a value for display
func (r *Reporter) formatValue(val string) string {
	if val == "" {
		return color.New(color.Faint).Sprint("(not set)")
	}
	return color.New(color.FgCyan).Sprint(val)
}

// PrintProgress prints a progress message
func (r *Reporter) PrintProgress(message string) {
	if r.verbose {
		color.Cyan("→ " + message)
	}
}
