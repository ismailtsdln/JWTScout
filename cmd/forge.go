package cmd

import (
	"fmt"
	"os"

	"github.com/ismailtsdln/JWTScout/internal/forge"
	"github.com/ismailtsdln/JWTScout/internal/parser"
	"github.com/spf13/cobra"
)

var (
	claims    []string
	secretKey string
	alg       string
	noSig     bool
)

var forgeCmd = &cobra.Command{
	Use:   "forge",
	Short: "Forge a modified JWT token",
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

		forger := forge.NewForger(token)

		// Apply claim modifications
		for _, c := range claims {
			forger.ParseClaimString(c)
		}

		signer := forge.NewSigner(forger)
		var forgedToken string

		if noSig {
			forgedToken, err = signer.GenerateUnsigned()
		} else if secretKey != "" {
			forgedToken, err = signer.GenerateHMAC(secretKey, alg)
		} else {
			rep.PrintError("Error: Either --secret or --no-sig must be provided for forging")
			return
		}

		if err != nil {
			rep.PrintError(fmt.Sprintf("Forging failed: %v", err))
			return
		}

		rep.PrintSuccess("Token successfully forged!")
		fmt.Printf("\nForged Token:\n%s\n", forgedToken)
	},
}

func init() {
	forgeCmd.Flags().StringSliceVarP(&claims, "claim", "c", []string{}, "Claims to modify (key=value)")
	forgeCmd.Flags().StringVarP(&secretKey, "secret", "s", "", "Secret key for HMAC signing")
	forgeCmd.Flags().StringVarP(&alg, "alg", "a", "HS256", "Algorithm to use for signing")
	forgeCmd.Flags().BoolVar(&noSig, "no-sig", false, "Generate unsigned token (alg:none)")
	rootCmd.AddCommand(forgeCmd)
}
