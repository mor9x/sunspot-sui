# Gnark - Sui

This directory contains tooling to generate a Sui Move verifier package from a
Gnark BN254 verifying key.

Unlike the Solana target, the Sui target does not embed the full verifier
implementation in the generated contract. Instead, it emits a Move package that
stores a prepared BN254 Groth16 verifying key and delegates verification to
`sui::groth16`.

By default, generated `Move.toml` files pin `Sui` using a git revision detected
from your local Sui checkout so the package can be built on other machines.
If you pass `--sui-framework-path`, the generator will instead emit a local
dependency, which is convenient for local development but not portable.

Current limitations:

- Only standard Groth16 proofs are supported.
- Gnark commitment extensions are not supported on the Sui target.
- Sui currently limits Groth16 verification to at most 8 public inputs.
