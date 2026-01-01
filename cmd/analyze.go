package cmd

import (
	"fmt"
	"os"

	"github.com/ismailtsdln/JWTScout/internal/attacker"
	"github.com/ismailtsdln/JWTScout/internal/parser"
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze a JWT token for security vulnerabilities",
	Run: func(cmd *cobra.Command, args []string) {
		if tokenArg == "" {
			fmt.Println("Error: --token flag is required")
			_ = cmd.Help()
			return
		}

		token, err := parser.ParseJWT(tokenArg)
		if err != nil {
			rep.PrintError(fmt.Sprintf("Failed to parse token: %v", err))
			os.Exit(1)
		}

		rep.PrintTokenInfo(token)

		analyzer := attacker.NewAnalyzer()
		findings := analyzer.Analyze(token)

		rep.PrintFindings(findings)

		// Check if any critical findings found for exit code
		hasCritical := false
		for _, f := range findings {
			if f.Severity.String() == "CRITICAL" {
				hasCritical = true
				break
			}
		}

		if hasCritical {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
}
