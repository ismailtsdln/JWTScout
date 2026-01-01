package cmd

import (
	"github.com/ismailtsdln/JWTScout/internal/reporter"
	"github.com/spf13/cobra"
)

var (
	tokenArg string
	verbose  bool
	rep      *reporter.Reporter
)

var rootCmd = &cobra.Command{
	Use:   "jwtscout",
	Short: "JWTScout is a JWT security testing tool",
	Long: `JWTScout is an offensive security utility used to analyze, audit, 
and exploit weaknesses in JSON Web Tokens (JWT).`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		rep = reporter.NewReporter(verbose)
		rep.PrintBanner()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&tokenArg, "token", "t", "", "JWT token to analyze")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}
