use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PasswordRequest {
    pub merkle_proof_bytes: Vec<u8>,
    pub index: usize,
    pub leaf_hash: [u8; 32],
    pub secret: [u8; 32],
    pub contribution: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Commitment {
    pub merkle_root: [u8; 32],
    pub contribution: [u8; 32],
}
