package cmd

import (
	"fmt"
	"os"

	"github.com/ismailtsdln/JWTScout/internal/brute"
	"github.com/ismailtsdln/JWTScout/internal/parser"
	"github.com/spf13/cobra"
)

var (
	wordlistPath string
	workers      int
)

var bruteCmd = &cobra.Command{
	Use:   "brute",
	Short: "Brute force HMAC secret for a token",
	Run: func(cmd *cobra.Command, args []string) {
		if tokenArg == "" || wordlistPath == "" {
			rep.PrintError("Error: --token and --wordlist flags are required")
			cmd.Help()
			return
		}

		token, err := parser.ParseJWT(tokenArg)
		if err != nil {
			rep.PrintError(fmt.Sprintf("Failed to parse token: %v", err))
			os.Exit(1)
		}

		rep.PrintInfo(fmt.Sprintf("Loading wordlist: %s", wordlistPath))
		words, err := brute.LoadWordlist(wordlistPath)
		if err != nil {
			rep.PrintError(fmt.Sprintf("Failed to load wordlist: %v", err))
			os.Exit(1)
		}

		rep.PrintInfo(fmt.Sprintf("Starting brute force against %s with %d workers...", token.Header.Alg, workers))

		bf, err := brute.NewBruteForcer(token, workers)
		if err != nil {
			rep.PrintError(err.Error())
			os.Exit(1)
		}

		secret, found := bf.BruteForce(words)
		if found {
			rep.PrintSuccess(fmt.Sprintf("SUCCESS! Secret found: %s", secret))
		} else {
			rep.PrintWarning("Failed to find secret. Try a larger wordlist.")
		}
	},
}

func init() {
	bruteCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "", "Path to wordlist file")
	bruteCmd.Flags().IntVarP(&workers, "workers", "n", 10, "Number of concurrent workers")
	rootCmd.AddCommand(bruteCmd)
}
