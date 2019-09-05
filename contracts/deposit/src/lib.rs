#![cfg_attr(not(any(test, feature = "std")), no_std)]

use core::option::Option;
use ink_core::{
    env::{ContractEnv, DefaultSrmlTypes, EnvTypes},
};
use ink_model::EnvHandler;
use scale::Codec;
use primitives::{
    events::*,
    traits::{Member, SimpleArithmetic},
};

pub mod default;
pub mod traits;

type AccountId = <ContractEnv<DefaultSrmlTypes> as EnvTypes>::AccountId;
type Balance = <ContractEnv<DefaultSrmlTypes> as EnvTypes>::Balance;
type BlockNumber = <ContractEnv<DefaultSrmlTypes> as EnvTypes>::BlockNumber;
type Hash = <ContractEnv<DefaultSrmlTypes> as EnvTypes>::Hash;

#[derive(Clone, scale::Encode, scale::Decode, PartialEq, Eq)]
#[cfg_attr(not(no_std), derive(Debug))]
pub struct CheckpointStatus {
    challengeable_until: BlockNumber,
    outstanding_challenges: u128,
}

impl ink_core::storage::Flush for CheckpointStatus {
	fn flush(&mut self) {}
}

#[cfg(not(any(test, feature = "std")))]
mod no_std {
	extern crate alloc;
	pub use alloc::string::{String, ToString};
	pub use alloc::vec::Vec;
}