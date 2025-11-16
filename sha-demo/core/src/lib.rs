use risc0_zkvm::sha::Digest;
use core::fmt::Debug;
use serde::{Deserialize, Serialize};

#[derive(Debug,Deserialize,Eq,PartialEq,Serialize)]

pub struct ShaInput {
    pub hash: Digest,
    pub date: u64 
}