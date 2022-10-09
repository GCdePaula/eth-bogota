#![no_main]

use password_checker_core::{Commitment, PasswordRequest};
use risc0_zkvm_guest::{env, sha};

use rs_merkle::{Hasher, MerkleProof};

#[derive(Clone)]
struct NativeHasher();

impl Hasher for NativeHasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let data: [u32; 8] =
            sha::digest_u8_slice(data).as_slice().try_into().unwrap();
        unsafe { core::mem::transmute(data) }
    }
}

risc0_zkvm_guest::entry!(main);
pub fn main() {
    let request: PasswordRequest = env::read();

    let secret_hash: [u8; 32] = {
        let data: [u32; 8] = sha::digest_u8_slice(&request.secret)
            .as_slice()
            .try_into()
            .unwrap();
        unsafe { core::mem::transmute(data) }
    };
    assert_eq!(secret_hash, request.leaf_hash);

    let merkle_proof: MerkleProof<NativeHasher> =
        request.merkle_proof_bytes.try_into().unwrap();
    let root = merkle_proof
        .root(&[request.index], &[request.leaf_hash], 256)
        .unwrap();

    let commitment = Commitment {
        merkle_root: root,
        contribution: request.contribution,
    };
    env::commit(&commitment);
}
