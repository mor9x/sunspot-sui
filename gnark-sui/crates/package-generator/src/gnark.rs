use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use std::error::Error;
use std::fs;
use std::io::{self, Cursor, Read};
use std::path::Path;

type DynError = Box<dyn Error>;

#[derive(Debug)]
pub struct GnarkVerifyingKey {
    pub nr_pubinputs: usize,
    pub alpha_g1: [u8; 64],
    pub beta_g2: [u8; 128],
    pub gamma_g2: [u8; 128],
    pub delta_g2: [u8; 128],
    pub k: Vec<[u8; 64]>,
    pub commitment_keys: Vec<[u8; 256]>,
    pub public_and_commitment_committed: Vec<Vec<u64>>,
}

#[derive(Debug)]
pub struct GnarkProof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
    pub commitments: Vec<[u8; 64]>,
}

#[derive(Debug)]
pub struct GnarkWitness {
    pub entries: Vec<[u8; 32]>,
}

pub fn load_vk(path: &Path) -> Result<GnarkVerifyingKey, DynError> {
    let bytes = fs::read(path)?;
    parse_vk(&bytes)
}

pub fn load_proof(path: &Path) -> Result<GnarkProof, DynError> {
    let bytes = fs::read(path)?;
    parse_proof(&bytes)
}

pub fn load_public_witness(path: &Path) -> Result<GnarkWitness, DynError> {
    let bytes = fs::read(path)?;
    parse_public_witness(&bytes)
}

pub fn g1_from_gnark_bytes(bytes: &[u8; 64]) -> Result<G1Affine, DynError> {
    let x = Fq::from_be_bytes_mod_order(&bytes[..32]);
    let y = Fq::from_be_bytes_mod_order(&bytes[32..64]);
    let point = G1Affine::new_unchecked(x, y);
    ensure_valid_g1(&point)?;
    Ok(point)
}

pub fn g2_from_gnark_bytes(bytes: &[u8; 128]) -> Result<G2Affine, DynError> {
    let x_1 = Fq::from_be_bytes_mod_order(&bytes[0..32]);
    let x_0 = Fq::from_be_bytes_mod_order(&bytes[32..64]);
    let y_1 = Fq::from_be_bytes_mod_order(&bytes[64..96]);
    let y_0 = Fq::from_be_bytes_mod_order(&bytes[96..128]);
    let point = G2Affine::new_unchecked(Fq2::new(x_0, x_1), Fq2::new(y_0, y_1));
    ensure_valid_g2(&point)?;
    Ok(point)
}

pub fn fr_from_gnark_bytes(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

fn parse_vk(bytes: &[u8]) -> Result<GnarkVerifyingKey, DynError> {
    let mut reader = Cursor::new(bytes);

    let alpha_g1 = read_fixed::<64>(&mut reader)?;
    let _beta_g1 = read_fixed::<64>(&mut reader)?;
    let beta_g2 = read_fixed::<128>(&mut reader)?;
    let gamma_g2 = read_fixed::<128>(&mut reader)?;
    let _delta_g1 = read_fixed::<64>(&mut reader)?;
    let delta_g2 = read_fixed::<128>(&mut reader)?;

    let k = read_vk_ic(&mut reader)?;
    let public_and_commitment_committed = read_matrix(&mut reader)?;
    let nb_commitment_keys = read_u32(&mut reader)? as usize;
    let mut commitment_keys = Vec::with_capacity(nb_commitment_keys);
    for _ in 0..nb_commitment_keys {
        commitment_keys.push(read_fixed::<256>(&mut reader)?);
    }

    let nr_pubinputs = k
        .len()
        .saturating_sub(1)
        .saturating_sub(commitment_keys.len());

    Ok(GnarkVerifyingKey {
        nr_pubinputs,
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        k,
        commitment_keys,
        public_and_commitment_committed,
    })
}

fn parse_proof(bytes: &[u8]) -> Result<GnarkProof, DynError> {
    if bytes.len() < 256 + 4 + 64 {
        return Err(err("gnark proof is too short"));
    }
    if !(bytes.len() - (256 + 4 + 64)).is_multiple_of(64) {
        return Err(err("gnark proof has an invalid length"));
    }

    let commitment_count = (bytes.len() - (256 + 4 + 64)) / 64;
    let encoded_count = u32::from_be_bytes(
        bytes[256..260]
            .try_into()
            .map_err(|_| err("failed to decode gnark proof commitment count"))?,
    ) as usize;
    if encoded_count != commitment_count {
        return Err(err(format!(
            "gnark proof commitment count mismatch: encoded={encoded_count}, derived={commitment_count}"
        )));
    }

    let mut a = [0u8; 64];
    a.copy_from_slice(&bytes[0..64]);
    let mut b = [0u8; 128];
    b.copy_from_slice(&bytes[64..192]);
    let mut c = [0u8; 64];
    c.copy_from_slice(&bytes[192..256]);

    let mut commitments = Vec::with_capacity(commitment_count);
    let mut offset = 260;
    for _ in 0..commitment_count {
        let mut commitment = [0u8; 64];
        commitment.copy_from_slice(&bytes[offset..offset + 64]);
        commitments.push(commitment);
        offset += 64;
    }

    Ok(GnarkProof {
        a,
        b,
        c,
        commitments,
    })
}

fn parse_public_witness(bytes: &[u8]) -> Result<GnarkWitness, DynError> {
    if bytes.len() < 12 {
        return Err(err("gnark public witness is too short"));
    }
    let payload = &bytes[12..];
    if !payload.len().is_multiple_of(32) {
        return Err(err(
            "gnark public witness payload is not a multiple of 32 bytes",
        ));
    }

    let encoded_count = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| err("failed to decode gnark public witness vector length"))?,
    ) as usize;
    let derived_count = payload.len() / 32;
    if encoded_count != derived_count {
        return Err(err(format!(
            "gnark public witness length mismatch: encoded={encoded_count}, derived={derived_count}"
        )));
    }

    let mut entries = Vec::with_capacity(derived_count);
    for chunk in payload.chunks_exact(32) {
        let mut entry = [0u8; 32];
        entry.copy_from_slice(chunk);
        entries.push(entry);
    }

    Ok(GnarkWitness { entries })
}

fn read_vk_ic(reader: &mut impl Read) -> io::Result<Vec<[u8; 64]>> {
    let count = read_u32(reader)? as usize;
    let mut vk_ic = Vec::with_capacity(count);
    for _ in 0..count {
        vk_ic.push(read_fixed::<64>(reader)?);
    }
    Ok(vk_ic)
}

fn read_matrix(reader: &mut impl Read) -> io::Result<Vec<Vec<u64>>> {
    let outer_len = read_u32(reader)? as usize;
    let mut result = Vec::with_capacity(outer_len);
    for _ in 0..outer_len {
        let inner_len = read_u32(reader)? as usize;
        let mut inner = Vec::with_capacity(inner_len);
        for _ in 0..inner_len {
            inner.push(read_u64(reader)?);
        }
        result.push(inner);
    }
    Ok(result)
}

fn read_fixed<const N: usize>(reader: &mut impl Read) -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn read_u64(reader: &mut impl Read) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

fn ensure_valid_g1(point: &G1Affine) -> Result<(), DynError> {
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(err("decoded G1 point is not in the BN254 subgroup"));
    }
    Ok(())
}

fn ensure_valid_g2(point: &G2Affine) -> Result<(), DynError> {
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(err("decoded G2 point is not in the BN254 subgroup"));
    }
    Ok(())
}

fn err(message: impl Into<String>) -> DynError {
    Box::new(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}
