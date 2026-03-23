mod gnark;

use ark_bn254::{Bn254, Fr};
use ark_ec::pairing::Pairing;
use ark_groth16::{Proof as ArkProof, VerifyingKey as ArkVerifyingKey};
use ark_serialize::CanonicalSerialize;
use gnark::{
    fr_from_gnark_bytes, g1_from_gnark_bytes, g2_from_gnark_bytes, load_proof, load_public_witness,
    load_vk,
};
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::ops::Neg;
use std::path::{Path, PathBuf};

type DynError = Box<dyn Error>;

const MAX_PUBLIC_INPUTS: usize = 8;

fn main() -> Result<(), DynError> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        return Err(usage_error());
    };

    match command.as_str() {
        "generate-package" => generate_package(parse_generate_package_args(args.collect())?),
        _ => Err(usage_error()),
    }
}

#[derive(Debug)]
struct GeneratePackageArgs {
    vk_path: PathBuf,
    out_dir: PathBuf,
    package_name: String,
    module_name: String,
    address_name: String,
    framework_path: Option<PathBuf>,
    proof_path: Option<PathBuf>,
    public_witness_path: Option<PathBuf>,
}

#[derive(Debug)]
struct PreparedVerifyingKeyBytes {
    vk_gamma_abc_g1_bytes: Vec<u8>,
    alpha_g1_beta_g2_bytes: Vec<u8>,
    gamma_g2_neg_pc_bytes: Vec<u8>,
    delta_g2_neg_pc_bytes: Vec<u8>,
}

enum SuiDependency {
    Local(PathBuf),
    GitRev(String),
}

fn parse_generate_package_args(args: Vec<String>) -> Result<GeneratePackageArgs, DynError> {
    let mut vk_path = None;
    let mut out_dir = None;
    let mut package_name = None;
    let mut module_name = None;
    let mut address_name = None;
    let mut framework_path = env::var_os("SUI_FRAMEWORK_PATH").map(PathBuf::from);
    let mut proof_path = None;
    let mut public_witness_path = None;

    let mut i = 0usize;
    while i < args.len() {
        let flag = &args[i];
        let value = |idx: &mut usize| -> Result<String, DynError> {
            *idx += 1;
            args.get(*idx)
                .cloned()
                .ok_or_else(|| err(format!("missing value for {flag}")))
        };

        match flag.as_str() {
            "--vk" => vk_path = Some(PathBuf::from(value(&mut i)?)),
            "--out" => out_dir = Some(PathBuf::from(value(&mut i)?)),
            "--package-name" => package_name = Some(value(&mut i)?),
            "--module-name" => module_name = Some(value(&mut i)?),
            "--address-name" => address_name = Some(value(&mut i)?),
            "--sui-framework-path" => framework_path = Some(PathBuf::from(value(&mut i)?)),
            "--proof" => proof_path = Some(PathBuf::from(value(&mut i)?)),
            "--public-witness" => public_witness_path = Some(PathBuf::from(value(&mut i)?)),
            other => return Err(err(format!("unknown flag: {other}"))),
        }
        i += 1;
    }

    let vk_path = vk_path.ok_or_else(|| err("missing required flag --vk"))?;
    let out_dir = out_dir.ok_or_else(|| err("missing required flag --out"))?;

    let stem = vk_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| err("failed to derive a name from the vk file"))?;
    let sanitized_stem = sanitize_identifier(stem, "verifier");

    Ok(GeneratePackageArgs {
        vk_path,
        out_dir,
        package_name: package_name.unwrap_or_else(|| format!("sunspot_{}_sui", sanitized_stem)),
        module_name: module_name.unwrap_or_else(|| "verifier".to_string()),
        address_name: address_name.unwrap_or_else(|| format!("sunspot_{}_sui", sanitized_stem)),
        framework_path,
        proof_path,
        public_witness_path,
    })
}

fn generate_package(args: GeneratePackageArgs) -> Result<(), DynError> {
    let package_name = sanitize_identifier(&args.package_name, "sunspot_sui");
    let module_name = sanitize_identifier(&args.module_name, "verifier");
    let address_name = sanitize_identifier(&args.address_name, "sunspot_sui");

    let vk = load_vk(&args.vk_path)?;
    ensure_supported_vk(&vk)?;
    let ark_vk = convert_vk(&vk)?;
    let pvk_bytes = prepare_vk_bytes(&ark_vk)?;

    let sui_dependency = if let Some(path) = args.framework_path {
        SuiDependency::Local(path)
    } else {
        let checkout_root = detect_local_sui_checkout().ok_or_else(|| {
            err(
                "failed to locate a local Sui checkout; pass --sui-framework-path or set SUI_FRAMEWORK_PATH",
            )
        })?;
        let revision = detect_git_revision(&checkout_root).ok_or_else(|| {
            err(
                "failed to determine the Sui git revision from the local checkout; pass --sui-framework-path for an explicit local dependency",
            )
        })?;
        SuiDependency::GitRev(revision)
    };

    fs::create_dir_all(args.out_dir.join("sources"))?;
    fs::write(
        args.out_dir.join("Move.toml"),
        render_move_toml(&package_name, &address_name, &sui_dependency),
    )?;
    fs::write(
        args.out_dir
            .join("sources")
            .join(format!("{module_name}.move")),
        render_move_module(&address_name, &module_name, &pvk_bytes),
    )?;
    fs::write(
        args.out_dir.join("README.md"),
        render_package_readme(&package_name, &module_name),
    )?;

    let artifacts_dir = args.out_dir.join("artifacts");
    let mut generated_artifacts = Vec::new();

    if let Some(proof_path) = args.proof_path {
        let proof = load_proof(&proof_path)?;
        if !proof.commitments.is_empty() {
            return Err(err(
                "Sui output does not support gnark proof commitments; this proof contains commitment openings",
            ));
        }
        fs::create_dir_all(&artifacts_dir)?;
        let bytes = serialize_proof(&proof)?;
        let bin_path = artifacts_dir.join("proof.bin");
        let hex_path = artifacts_dir.join("proof.hex");
        fs::write(&bin_path, &bytes)?;
        fs::write(&hex_path, hex_string(&bytes))?;
        generated_artifacts.push(bin_path);
        generated_artifacts.push(hex_path);
    }

    if let Some(public_witness_path) = args.public_witness_path {
        let witness = load_public_witness(&public_witness_path)?;
        if witness.entries.len() != vk.nr_pubinputs {
            return Err(err(format!(
                "public witness count mismatch: witness has {}, vk expects {}",
                witness.entries.len(),
                vk.nr_pubinputs
            )));
        }
        fs::create_dir_all(&artifacts_dir)?;
        let bytes = serialize_public_inputs(&witness.entries)?;
        let bin_path = artifacts_dir.join("public_inputs.bin");
        let hex_path = artifacts_dir.join("public_inputs.hex");
        fs::write(&bin_path, &bytes)?;
        fs::write(&hex_path, hex_string(&bytes))?;
        generated_artifacts.push(bin_path);
        generated_artifacts.push(hex_path);
    }

    println!("Generated Sui package: {}", args.out_dir.display());
    println!("  Move.toml: {}", args.out_dir.join("Move.toml").display());
    println!(
        "  Module: {}",
        args.out_dir
            .join("sources")
            .join(format!("{module_name}.move"))
            .display()
    );
    if !generated_artifacts.is_empty() {
        println!("Generated Sui runtime artifacts:");
        for path in generated_artifacts {
            println!("  {}", path.display());
        }
    }

    Ok(())
}

fn ensure_supported_vk(vk: &gnark::GnarkVerifyingKey) -> Result<(), DynError> {
    if !vk.commitment_keys.is_empty() || !vk.public_and_commitment_committed.is_empty() {
        return Err(err(
            "Sui output currently supports only standard Groth16 VKs without gnark commitment extensions",
        ));
    }
    if vk.nr_pubinputs > MAX_PUBLIC_INPUTS {
        return Err(err(format!(
            "Sui groth16 supports at most {MAX_PUBLIC_INPUTS} public inputs, but this VK requires {}",
            vk.nr_pubinputs
        )));
    }
    Ok(())
}

fn convert_vk(vk: &gnark::GnarkVerifyingKey) -> Result<ArkVerifyingKey<Bn254>, DynError> {
    let alpha_g1 = g1_from_gnark_bytes(&vk.alpha_g1)?;
    let beta_g2 = g2_from_gnark_bytes(&vk.beta_g2)?;
    let gamma_g2 = g2_from_gnark_bytes(&vk.gamma_g2)?;
    let delta_g2 = g2_from_gnark_bytes(&vk.delta_g2)?;

    let mut gamma_abc_g1 = Vec::with_capacity(vk.k.len());
    for point in &vk.k {
        gamma_abc_g1.push(g1_from_gnark_bytes(point)?);
    }

    Ok(ArkVerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}

fn prepare_vk_bytes(vk: &ArkVerifyingKey<Bn254>) -> Result<PreparedVerifyingKeyBytes, DynError> {
    let mut vk_gamma_abc_g1_bytes = Vec::new();
    for g1 in &vk.gamma_abc_g1 {
        g1.serialize_compressed(&mut vk_gamma_abc_g1_bytes)?;
    }

    let mut alpha_g1_beta_g2_bytes = Vec::new();
    Bn254::pairing(vk.alpha_g1, vk.beta_g2)
        .0
        .serialize_compressed(&mut alpha_g1_beta_g2_bytes)?;

    let mut gamma_g2_neg_pc_bytes = Vec::new();
    vk.gamma_g2
        .neg()
        .serialize_compressed(&mut gamma_g2_neg_pc_bytes)?;

    let mut delta_g2_neg_pc_bytes = Vec::new();
    vk.delta_g2
        .neg()
        .serialize_compressed(&mut delta_g2_neg_pc_bytes)?;

    Ok(PreparedVerifyingKeyBytes {
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
    })
}

fn serialize_proof(proof: &gnark::GnarkProof) -> Result<Vec<u8>, DynError> {
    let ark_proof = ArkProof::<Bn254> {
        a: g1_from_gnark_bytes(&proof.a)?,
        b: g2_from_gnark_bytes(&proof.b)?,
        c: g1_from_gnark_bytes(&proof.c)?,
    };
    let mut bytes = Vec::new();
    ark_proof.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

fn serialize_public_inputs(entries: &[[u8; 32]]) -> Result<Vec<u8>, DynError> {
    if entries.len() > MAX_PUBLIC_INPUTS {
        return Err(err(format!(
            "Sui groth16 supports at most {MAX_PUBLIC_INPUTS} public inputs, got {}",
            entries.len()
        )));
    }
    let mut bytes = Vec::new();
    for entry in entries {
        let fr = fr_from_gnark_bytes(entry);
        serialize_scalar(&fr, &mut bytes)?;
    }
    Ok(bytes)
}

fn serialize_scalar(scalar: &Fr, output: &mut Vec<u8>) -> Result<(), DynError> {
    scalar.serialize_compressed(output)?;
    Ok(())
}

fn render_move_toml(
    package_name: &str,
    address_name: &str,
    sui_dependency: &SuiDependency,
) -> String {
    let dependency = match sui_dependency {
        SuiDependency::Local(framework_path) => {
            let framework_path = framework_path.to_string_lossy().replace('\\', "/");
            format!("Sui = {{ local = \"{framework_path}\" }}")
        }
        SuiDependency::GitRev(rev) => format!(
            "Sui = {{ git = \"https://github.com/MystenLabs/sui.git\", subdir = \"crates/sui-framework/packages/sui-framework\", rev = \"{rev}\" }}"
        ),
    };
    format!(
        "[package]\nname = \"{package_name}\"\nversion = \"0.0.1\"\nedition = \"2024.beta\"\n\n[dependencies]\n{dependency}\n\n[addresses]\n{address_name} = \"0x0\"\n"
    )
}

fn render_move_module(
    address_name: &str,
    module_name: &str,
    pvk: &PreparedVerifyingKeyBytes,
) -> String {
    format!(
        "// This file is generated by gnark-sui-package-generator.\nmodule {address_name}::{module_name};\n\nuse sui::groth16;\n\nconst VK_GAMMA_ABC_G1_BYTES: vector<u8> = x\"{vk_gamma_abc_g1}\";\nconst ALPHA_G1_BETA_G2_BYTES: vector<u8> = x\"{alpha_g1_beta_g2}\";\nconst GAMMA_G2_NEG_PC_BYTES: vector<u8> = x\"{gamma_g2_neg_pc}\";\nconst DELTA_G2_NEG_PC_BYTES: vector<u8> = x\"{delta_g2_neg_pc}\";\n\npublic fun prepared_verifying_key(): groth16::PreparedVerifyingKey {{\n    groth16::pvk_from_bytes(\n        VK_GAMMA_ABC_G1_BYTES,\n        ALPHA_G1_BETA_G2_BYTES,\n        GAMMA_G2_NEG_PC_BYTES,\n        DELTA_G2_NEG_PC_BYTES,\n    )\n}}\n\npublic fun verify(public_inputs_bytes: vector<u8>, proof_points_bytes: vector<u8>): bool {{\n    let curve = groth16::bn254();\n    let pvk = prepared_verifying_key();\n    let public_inputs = groth16::public_proof_inputs_from_bytes(public_inputs_bytes);\n    let proof_points = groth16::proof_points_from_bytes(proof_points_bytes);\n    groth16::verify_groth16_proof(&curve, &pvk, &public_inputs, &proof_points)\n}}\n",
        vk_gamma_abc_g1 = hex_string(&pvk.vk_gamma_abc_g1_bytes),
        alpha_g1_beta_g2 = hex_string(&pvk.alpha_g1_beta_g2_bytes),
        gamma_g2_neg_pc = hex_string(&pvk.gamma_g2_neg_pc_bytes),
        delta_g2_neg_pc = hex_string(&pvk.delta_g2_neg_pc_bytes),
    )
}

fn render_package_readme(package_name: &str, module_name: &str) -> String {
    format!(
        "# {package_name}\n\nGenerated by `sunspot deploy-sui`.\n\nBuild the package with:\n\n```bash\nsui move build\n```\n\nThe generated module is `{module_name}` and exposes:\n\n- `prepared_verifying_key()`: returns the embedded prepared BN254 Groth16 verifying key.\n- `verify(public_inputs_bytes, proof_points_bytes)`: verifies serialized public inputs and proof bytes using `sui::groth16`.\n\nIf `artifacts/` exists, it contains off-chain converted runtime inputs:\n\n- `artifacts/proof.bin`: arkworks-compressed BN254 Groth16 proof bytes.\n- `artifacts/public_inputs.bin`: arkworks-compressed BN254 public input bytes.\n"
    )
}

fn sanitize_identifier(input: &str, fallback: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str(fallback);
    }
    if out.as_bytes()[0].is_ascii_digit() {
        out.insert_str(0, "sunspot_");
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    out.trim_matches('_').to_string().if_empty(fallback)
}

trait IfEmpty {
    fn if_empty(self, fallback: &str) -> String;
}

impl IfEmpty for String {
    fn if_empty(self, fallback: &str) -> String {
        if self.is_empty() {
            fallback.to_string()
        } else {
            self
        }
    }
}

fn detect_local_sui_checkout() -> Option<PathBuf> {
    let home = env::var_os("HOME")?;
    let checkouts_dir = PathBuf::from(home)
        .join(".cargo")
        .join("git")
        .join("checkouts");
    let mut candidates = Vec::new();

    for checkout in fs::read_dir(checkouts_dir).ok()? {
        let checkout = checkout.ok()?;
        let file_name = checkout.file_name();
        let file_name = file_name.to_string_lossy();
        if !file_name.starts_with("sui-") {
            continue;
        }
        for revision in fs::read_dir(checkout.path()).ok()? {
            let revision = revision.ok()?;
            let root = revision.path();
            let candidate = root
                .join("crates")
                .join("sui-framework")
                .join("packages")
                .join("sui-framework");
            if candidate.exists() {
                candidates.push(root);
            }
        }
    }

    candidates.sort();
    candidates.pop()
}

fn detect_git_revision(repo_root: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let revision = String::from_utf8(output.stdout).ok()?;
    let revision = revision.trim();
    if revision.is_empty() {
        None
    } else {
        Some(revision.to_string())
    }
}

fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn usage_error() -> DynError {
    err("usage: gnark-sui-package-generator generate-package --vk <file.vk> --out <output_dir> [--package-name <name>] [--module-name <name>] [--address-name <name>] [--sui-framework-path <path>] [--proof <file.proof>] [--public-witness <file.pw>]")
}

fn err(message: impl Into<String>) -> DynError {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq, Fr};
    use ark_ff::{BigInteger, PrimeField};
    use ark_groth16::Groth16;
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Clone)]
    struct SumCircuit {
        a: Fr,
        b: Fr,
        c: Fr,
    }

    impl ConstraintSynthesizer<Fr> for SumCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let a_var = cs.new_witness_variable(|| Ok(self.a))?;
            let b_var = cs.new_witness_variable(|| Ok(self.b))?;
            let c_var = cs.new_input_variable(|| Ok(self.c))?;

            cs.enforce_constraint(
                lc!() + a_var + b_var,
                lc!() + ark_relations::r1cs::Variable::One,
                lc!() + c_var,
            )
        }
    }

    #[test]
    fn generates_move_package_from_standard_groth16_fixture() {
        let rng = &mut StdRng::seed_from_u64(42);
        let a = Fr::from(2u64);
        let b = Fr::from(3u64);
        let c = a + b;
        let circuit = SumCircuit { a, b, c };

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, rng).unwrap();

        let temp_root = unique_temp_dir("gnark_sui_test");
        let package_dir = temp_root.join("package");
        let framework_dir = detect_local_sui_checkout()
            .expect("local Sui checkout should exist for tests")
            .join("crates")
            .join("sui-framework")
            .join("packages")
            .join("sui-framework");

        let vk_path = temp_root.join("fixture.vk");
        fs::write(&vk_path, encode_gnark_vk(&vk)).unwrap();

        let proof_path = temp_root.join("fixture.proof");
        fs::write(&proof_path, encode_gnark_proof(&proof)).unwrap();

        let witness_path = temp_root.join("fixture.pw");
        fs::write(&witness_path, encode_gnark_public_witness(&[c])).unwrap();

        generate_package(GeneratePackageArgs {
            vk_path,
            out_dir: package_dir.clone(),
            package_name: "fixture_pkg".to_string(),
            module_name: "fixture_verifier".to_string(),
            address_name: "fixture_pkg".to_string(),
            framework_path: Some(framework_dir),
            proof_path: Some(proof_path),
            public_witness_path: Some(witness_path),
        })
        .unwrap();

        let move_toml = fs::read_to_string(package_dir.join("Move.toml")).unwrap();
        assert!(move_toml.contains("fixture_pkg"));

        let module = fs::read_to_string(package_dir.join("sources/fixture_verifier.move")).unwrap();
        assert!(module.contains("module fixture_pkg::fixture_verifier;"));
        assert!(module.contains("public fun verify("));

        let proof_bytes = fs::read(package_dir.join("artifacts/proof.bin")).unwrap();
        assert!(!proof_bytes.is_empty());

        let public_input_bytes = fs::read(package_dir.join("artifacts/public_inputs.bin")).unwrap();
        assert_eq!(public_input_bytes.len(), 32);

        let status = std::process::Command::new("sui")
            .args(["move", "build"])
            .current_dir(&package_dir)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}_{timestamp}_{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn encode_gnark_vk(vk: &ArkVerifyingKey<Bn254>) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&g1_to_gnark_bytes(&vk.alpha_g1));
        bytes.extend_from_slice(&[0u8; 64]);
        bytes.extend_from_slice(&g2_to_gnark_bytes(&vk.beta_g2));
        bytes.extend_from_slice(&g2_to_gnark_bytes(&vk.gamma_g2));
        bytes.extend_from_slice(&[0u8; 64]);
        bytes.extend_from_slice(&g2_to_gnark_bytes(&vk.delta_g2));
        bytes.extend_from_slice(&(vk.gamma_abc_g1.len() as u32).to_be_bytes());
        for point in &vk.gamma_abc_g1 {
            bytes.extend_from_slice(&g1_to_gnark_bytes(point));
        }
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes
    }

    fn encode_gnark_proof(proof: &ArkProof<Bn254>) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&g1_to_gnark_bytes(&proof.a));
        bytes.extend_from_slice(&g2_to_gnark_bytes(&proof.b));
        bytes.extend_from_slice(&g1_to_gnark_bytes(&proof.c));
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        bytes
    }

    fn encode_gnark_public_witness(public_inputs: &[Fr]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let len = public_inputs.len() as u32;
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&len.to_be_bytes());
        for scalar in public_inputs {
            bytes.extend_from_slice(&fr_to_be_bytes(scalar));
        }
        bytes
    }

    fn g1_to_gnark_bytes(point: &ark_bn254::G1Affine) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(&fq_to_be_bytes(&point.x));
        out[32..64].copy_from_slice(&fq_to_be_bytes(&point.y));
        out
    }

    fn g2_to_gnark_bytes(point: &ark_bn254::G2Affine) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[0..32].copy_from_slice(&fq_to_be_bytes(&point.x.c1));
        out[32..64].copy_from_slice(&fq_to_be_bytes(&point.x.c0));
        out[64..96].copy_from_slice(&fq_to_be_bytes(&point.y.c1));
        out[96..128].copy_from_slice(&fq_to_be_bytes(&point.y.c0));
        out
    }

    fn fq_to_be_bytes(value: &Fq) -> [u8; 32] {
        bigint_to_be_32(&value.into_bigint())
    }

    fn fr_to_be_bytes(value: &Fr) -> [u8; 32] {
        bigint_to_be_32(&value.into_bigint())
    }

    fn bigint_to_be_32(value: &impl BigInteger) -> [u8; 32] {
        let encoded = value.to_bytes_be();
        let mut out = [0u8; 32];
        let start = 32 - encoded.len();
        out[start..].copy_from_slice(&encoded);
        out
    }
}
