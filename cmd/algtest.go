package cmd

import (
	"fmt"
	"os"

	"github.com/ismailtasdelen/JWTScout/internal/attacker"
	"github.com/ismailtasdelen/JWTScout/internal/parser"
	"github.com/spf13/cobra"
)

var algTestCmd = &cobra.Command{
	Use:   "alg-test",
	Short: "Test a token for algorithm-related vulnerabilities",
	Run: func(cmd *cobra.Command, args []string) {
		if tokenArg == "" {
			rep.PrintError("Error: --token flag is required")
			cmd.Help()
			return
		}

		token, err := parser.ParseJWT(tokenArg)
		if err != nil {
			rep.PrintError(fmt.Sprintf("Failed to parse token: %v", err))
			os.Exit(1)
		}

		at := attacker.NewAlgTest()
		results := at.TestAll(token)

		if len(results) == 0 {
			rep.PrintInfo("No standard algorithm tests applicable to this token.")
			return
		}

		rep.PrintSeparator()
		fmt.Printf("🧪 Algorithm Vulnerability Tests (%d variants generated)\n", len(results))
		rep.PrintSeparator()

		for _, res := range results {
			fmt.Printf("\n[+] Test: %s\n", res.TestName)
			fmt.Printf("    Desc: %s\n", res.Description)
			fmt.Printf("    Token: %s\n", res.Payload)
		}
		fmt.Println()
	},
}

func init() {
	rootCmd.AddCommand(algTestCmd)
}
