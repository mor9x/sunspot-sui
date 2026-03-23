package cmd

import (
	"fmt"
	"os"
	"sunspot/go/bn254"

	"github.com/consensys/gnark/constraint"
	"github.com/spf13/cobra"
)

type E = constraint.U64
type T = *bn254.BN254Field

var rootCmd = &cobra.Command{
	Use:   "sunspot",
	Short: "Sunspot provides tooling for noir circuits on Solana and Sui",
	Long:  "Sunspot provides tooling for Noir circuits on Solana and Sui — including compilation, proof generation, verification, and verifier package generation using Groth16.",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Add subcommands here
	rootCmd.AddCommand(compileCmd)
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(proveCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(deployCmd)
	rootCmd.AddCommand(deploySuiCmd)
}
