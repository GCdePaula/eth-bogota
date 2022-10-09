use std::fs;

use password_checker_core::{Commitment, PasswordRequest};
use password_checker_methods::{PW_CHECKER_ID, PW_CHECKER_PATH};
use risc0_zkp::core::sha::Digest;
use risc0_zkp::core::sha::{self, Sha};
use risc0_zkvm::host::Prover;
use risc0_zkvm::serde::{from_slice, to_vec};

use rs_merkle::{Hasher, MerkleProof, MerkleTree};

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

fn main() {
    let secrets = [
        NativeHasher::hash("a".as_bytes()),
        NativeHasher::hash("b".as_bytes()),
        NativeHasher::hash("c".as_bytes()),
        NativeHasher::hash("d".as_bytes()),
    ];

    let contribution = NativeHasher::hash("hello".as_bytes());

    let mut merkle_tree = MerkleTree::<NativeHasher>::new();
    merkle_tree.insert(NativeHasher::hash(&secrets[0]));
    merkle_tree.insert(NativeHasher::hash(&secrets[1]));
    merkle_tree.insert(NativeHasher::hash(&secrets[2]));
    merkle_tree.insert(NativeHasher::hash(&secrets[3]));

    let zero_hash: [u8; 32] = [0; 32];
    for _ in 0..251 {
        merkle_tree.insert(zero_hash);
    }
    merkle_tree.commit();

    println!("tree depth = {}", merkle_tree.depth());
    println!("tree root = {:?}", merkle_tree.root());
    println!("contribution = {:?}", contribution);

    let request = PasswordRequest {
        merkle_proof_bytes: merkle_tree.proof(&[0]).to_bytes(),
        index: 0,
        leaf_hash: NativeHasher::hash(&secrets[0]),
        secret: secrets[0],
        contribution,
    };

    println!("method ID: {:?}", PW_CHECKER_ID);

    // a new prover is created to run the pw_checker method
    let elf_contents = fs::read(PW_CHECKER_PATH).unwrap();
    let mut prover = Prover::new(&elf_contents, PW_CHECKER_ID).unwrap();

    // Adding input to the prover makes it readable by the guest
    let vec = to_vec(&request).unwrap();
    prover.add_input(&vec).unwrap();

    let receipt = prover.run().unwrap();
    let commitment: Commitment =
        from_slice(&receipt.get_journal_vec().unwrap()).unwrap();
    println!("Root hash is: {:?}", &commitment.merkle_root);
    println!("Contribution: {:?}", &commitment.contribution);

    // In most scenarios, we would serialize and send the receipt to a verifier here
    // The verifier checks the receipt with the following call, which panics if the receipt is wrong
    // receipt.verify(PW_CHECKER_ID).unwrap();
}
