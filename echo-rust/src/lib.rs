use password_checker_core::Commitment;
use password_checker_methods::PW_CHECKER_ID;
use risc0_zkp::core::sha::{self, Sha};
use risc0_zkvm::host::Receipt;
use risc0_zkvm::serde::from_slice;
use rs_merkle::{Hasher, MerkleProof, MerkleTree};

use anyhow::{bail, Result};

#[derive(Clone)]
struct NativeHasher();

impl Hasher for NativeHasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let data: [u32; 8] = sha::DefaultImplementation {}
            .hash_bytes(data)
            .as_slice()
            .try_into()
            .unwrap();
        unsafe { core::mem::transmute(data) }
    }
}

pub struct State {
    merkle_hash: [u8; 32],
    leaves_count: usize,
    contributions: Vec<[u8; 32]>,
}

impl State {
    pub fn new() -> Self {
        let mut merkle_tree = MerkleTree::<NativeHasher>::new();

        let zero_hash: [u8; 32] = [0; 32];
        for _ in 0..255 {
            merkle_tree.insert(zero_hash);
        }
        merkle_tree.commit();

        Self {
            merkle_hash: merkle_tree.root().unwrap(),
            leaves_count: 0,
            contributions: Vec::new(),
        }
    }

    pub fn add_contributor(
        &mut self,
        merkle_proof: Vec<u8>,
        contributor: [u8; 32],
    ) -> Result<()> {
        let proof: MerkleProof<NativeHasher> = match merkle_proof.try_into() {
            Ok(p) => p,
            Err(e) => bail!("Failed to parse proof: {}", e),
        };

        let root = match proof.root(&[self.leaves_count], &[[0; 32]], 256) {
            Ok(p) => p,
            Err(e) => bail!("Failed to calculate root: {}", e),
        };

        if root != self.merkle_hash {
            bail!("Proof doesn't match");
        }

        let mut proof_hashes = proof.proof_hashes().to_vec();
        proof_hashes[self.leaves_count] = contributor;
        let new_proof = MerkleProof::<NativeHasher>::new(proof_hashes);

        let new_root =
            match new_proof.root(&[self.leaves_count], &[contributor], 256) {
                Ok(p) => p,
                Err(e) => bail!("Failed to calculate new root: {}", e),
            };

        self.merkle_hash = new_root;
        self.leaves_count += 1;

        Ok(())
    }

    pub fn remove_contributor(
        &mut self,
        merkle_proof: Vec<u8>,
        contributor: [u8; 32],
    ) -> Result<()> {
        let proof: MerkleProof<NativeHasher> = match merkle_proof.try_into() {
            Ok(p) => p,
            Err(e) => bail!("Failed to parse proof: {}", e),
        };

        let root = match proof.root(&[self.leaves_count], &[contributor], 256) {
            Ok(p) => p,
            Err(e) => bail!("Failed to calculate root: {}", e),
        };

        if root != self.merkle_hash {
            bail!("Proof doesn't match");
        }

        let mut proof_hashes = proof.proof_hashes().to_vec();
        proof_hashes[self.leaves_count] = [0; 32];
        let new_proof = MerkleProof::<NativeHasher>::new(proof_hashes);

        let new_root =
            match new_proof.root(&[self.leaves_count], &[[0; 32]], 256) {
                Ok(p) => p,
                Err(e) => bail!("Failed to calculate new root: {}", e),
            };

        self.merkle_hash = new_root;
        self.leaves_count += 1;

        Ok(())
    }

    pub fn add_contribution(
        &mut self,
        zk_proof: Vec<u8>,
        contribution: [u8; 32],
    ) -> Result<()> {
        let receipt: Receipt = bincode::deserialize(&zk_proof)?;
        receipt.verify(PW_CHECKER_ID)?;

        let commitment: Commitment =
            from_slice(&receipt.get_journal_vec().unwrap()).unwrap();

        if commitment.merkle_root != self.merkle_hash {
            bail!("Proof doesn't match");
        }

        self.contributions.push(contribution);

        Ok(())
    }
}
