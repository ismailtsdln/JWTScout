package cmd

import (
	"fmt"
	"os"

	"github.com/ismailtsdln/JWTScout/internal/attacker"
	"github.com/ismailtsdln/JWTScout/internal/parser"
	"github.com/spf13/cobra"
)

var kidTestCmd = &cobra.Command{
	Use:   "kid-test",
	Short: "Test a token for kid header vulnerabilities",
	Run: func(cmd *cobra.Command, args []string) {
		if tokenArg == "" {
			rep.PrintError("Error: --token flag is required")
			_ = cmd.Help()
			return
		}

		token, err := parser.ParseJWT(tokenArg)
		if err != nil {
			rep.PrintError(fmt.Sprintf("Failed to parse token: %v", err))
			os.Exit(1)
		}

		kt := attacker.NewKidTest()
		results := kt.TestAll(token)

		rep.PrintSeparator()
		fmt.Printf("🧪 kid Injection Tests (%d variants generated)\n", len(results))
		rep.PrintSeparator()

		for _, res := range results {
			fmt.Printf("\n[+] Test: %s\n", res.TestName)
			fmt.Printf("    Desc: %s\n", res.Description)
			fmt.Printf("    kid:  %s\n", res.KidValue)
			fmt.Printf("    Token: %s\n", res.Token)
		}
		fmt.Println()
	},
}

func init() {
	rootCmd.AddCommand(kidTestCmd)
}
