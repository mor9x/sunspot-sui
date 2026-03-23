package cmd

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	deploySuiOutDir            string
	deploySuiPackageName       string
	deploySuiModuleName        string
	deploySuiAddressName       string
	deploySuiFrameworkPath     string
	deploySuiProofPath         string
	deploySuiPublicWitnessPath string
)

var deploySuiCmd = &cobra.Command{
	Use:   "deploy-sui <path/to/file.vk>",
	Short: "Generate a Sui Move verifier package with the given verification key",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		vkPath := mustAbsExistingFile(args[0], ".vk")
		vkDir := filepath.Dir(vkPath)
		vkBase := strings.TrimSuffix(filepath.Base(vkPath), filepath.Ext(vkPath))

		outDir := deploySuiOutDir
		if outDir == "" {
			outDir = filepath.Join(vkDir, vkBase+"-sui")
		}
		outDir = mustAbsPath(outDir)

		generatorManifest := resolveSuiGeneratorManifest()

		cargoArgs := []string{
			"run",
			"--manifest-path",
			generatorManifest,
			"--",
			"generate-package",
			"--vk",
			vkPath,
			"--out",
			outDir,
		}

		if deploySuiPackageName != "" {
			cargoArgs = append(cargoArgs, "--package-name", deploySuiPackageName)
		}
		if deploySuiModuleName != "" {
			cargoArgs = append(cargoArgs, "--module-name", deploySuiModuleName)
		}
		if deploySuiAddressName != "" {
			cargoArgs = append(cargoArgs, "--address-name", deploySuiAddressName)
		}
		if deploySuiFrameworkPath != "" {
			cargoArgs = append(cargoArgs, "--sui-framework-path", mustAbsPath(deploySuiFrameworkPath))
		}
		if deploySuiProofPath != "" {
			cargoArgs = append(cargoArgs, "--proof", mustAbsExistingFile(deploySuiProofPath, ".proof"))
		}
		if deploySuiPublicWitnessPath != "" {
			cargoArgs = append(cargoArgs, "--public-witness", mustAbsExistingFile(deploySuiPublicWitnessPath, ".pw"))
		}

		cargoCmd := exec.Command("cargo", cargoArgs...)
		cargoCmd.Stdout = os.Stdout
		cargoCmd.Stderr = os.Stderr
		cargoCmd.Env = os.Environ()

		fmt.Println("Generating Sui Move verifier package...")
		if err := cargoCmd.Run(); err != nil {
			log.Fatalf("failed to generate Sui package: %v", err)
		}

		fmt.Println("Sui package generated successfully:")
		fmt.Println("  Package:", outDir)
		fmt.Println("  Build with: cd", outDir, "&& sui move build")
	},
}

func init() {
	deploySuiCmd.Flags().StringVar(&deploySuiOutDir, "out-dir", "", "output directory for the generated Sui Move package")
	deploySuiCmd.Flags().StringVar(&deploySuiPackageName, "package-name", "", "Move package name to generate")
	deploySuiCmd.Flags().StringVar(&deploySuiModuleName, "module-name", "", "Move module name to generate")
	deploySuiCmd.Flags().StringVar(&deploySuiAddressName, "address-name", "", "named address to use in Move.toml")
	deploySuiCmd.Flags().StringVar(&deploySuiFrameworkPath, "sui-framework-path", "", "local path to the Sui framework package")
	deploySuiCmd.Flags().StringVar(&deploySuiProofPath, "proof", "", "optional gnark proof file to convert into Sui proof bytes")
	deploySuiCmd.Flags().StringVar(&deploySuiPublicWitnessPath, "public-witness", "", "optional gnark public witness file to convert into Sui public input bytes")
}

func resolveSuiGeneratorManifest() string {
	if env := os.Getenv("GNARK_SUI_PACKAGE_GENERATOR"); env != "" {
		manifest := env
		info, err := os.Stat(manifest)
		if err != nil {
			log.Fatalf("GNARK_SUI_PACKAGE_GENERATOR does not exist: %s", manifest)
		}
		if info.IsDir() {
			manifest = filepath.Join(manifest, "Cargo.toml")
		}
		return mustAbsExistingPath(manifest)
	}

	for _, candidate := range generatorManifestCandidates() {
		if _, err := os.Stat(candidate); err == nil {
			return mustAbsExistingPath(candidate)
		}
	}

	log.Fatalf(
		"could not locate gnark-sui package generator.\n" +
			"Set GNARK_SUI_PACKAGE_GENERATOR to the generator crate or its Cargo.toml,\n" +
			"or run this binary from a checkout/package layout that includes gnark-sui.",
	)
	return ""
}

func generatorManifestCandidates() []string {
	candidates := []string{
		filepath.Join("gnark-sui", "crates", "package-generator", "Cargo.toml"),
		filepath.Join("..", "gnark-sui", "crates", "package-generator", "Cargo.toml"),
	}

	exePath, err := os.Executable()
	if err != nil {
		return candidates
	}
	exeDir := filepath.Dir(exePath)
	candidates = append(candidates,
		filepath.Join(exeDir, "gnark-sui", "crates", "package-generator", "Cargo.toml"),
		filepath.Join(exeDir, "..", "gnark-sui", "crates", "package-generator", "Cargo.toml"),
		filepath.Join(exeDir, "..", "share", "sunspot", "gnark-sui", "crates", "package-generator", "Cargo.toml"),
	)
	return candidates
}

func mustAbsExistingFile(path string, wantExt string) string {
	if filepath.Ext(path) != wantExt {
		log.Fatalf("invalid input file: %s (must end with %s)", path, wantExt)
	}
	abs := mustAbsExistingPath(path)
	info, err := os.Stat(abs)
	if err != nil {
		log.Fatalf("path does not exist: %s", abs)
	}
	if info.IsDir() {
		log.Fatalf("expected a file, got a directory: %s", abs)
	}
	return abs
}

func mustAbsExistingPath(path string) string {
	abs := mustAbsPath(path)
	if _, err := os.Stat(abs); err != nil {
		log.Fatalf("path does not exist: %s", abs)
	}
	return abs
}

func mustAbsPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		log.Fatalf("failed to resolve path %s: %v", path, err)
	}
	return abs
}
