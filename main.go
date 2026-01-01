package main

import (
	"os"

	"github.com/ismailtasdelen/JWTScout/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
