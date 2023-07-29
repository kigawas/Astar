#![cfg_attr(not(feature = "std"), no_std)]
use frame_support::traits::Randomness;
use pallet_contracts::chain_extension::{ChainExtension, Environment, Ext, InitState, RetVal};
use sp_core::Encode;
use sp_runtime::DispatchError;
use sp_std::{marker::PhantomData, vec::Vec};

use libsecp256k1::SecretKey;

mod utils;
use utils::{encrypt, NONCE_LENGTH};

enum EciesFuncId {
    Encrypt,
}

impl TryFrom<u16> for EciesFuncId {
    type Error = DispatchError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EciesFuncId::Encrypt),
            _ => Err(DispatchError::Other(
                "Unsupported func id in ecies chain extension",
            )),
        }
    }
}

/// Contract extension for `ECIES`
pub struct EciesExtension<T>(PhantomData<T>);

impl<T> Default for EciesExtension<T> {
    fn default() -> Self {
        EciesExtension(PhantomData)
    }
}

impl<T> ChainExtension<T> for EciesExtension<T>
where
    T: pallet_contracts::Config,
{
    fn call<E: Ext>(&mut self, env: Environment<E, InitState>) -> Result<RetVal, DispatchError>
    where
        E: Ext<T = T>,
    {
        let func_id = env.func_id().try_into()?;
        match func_id {
            EciesFuncId::Encrypt => {
                let mut env = env.buf_in_buf_out();
                let (pk, msg): (Vec<u8>, Vec<u8>) = env.read_as_unbounded(env.in_len())?;
                loop {
                    let nonce_output = T::Randomness::random(&msg).0; //TODO: VRF
                    let nonce = nonce_output.encode();

                    let sk_output = T::Randomness::random(&nonce).0; //TODO: VRF
                    let sk = sk_output.encode();

                    if let Ok(ephemeral_sk) = SecretKey::parse_slice(&sk) {
                        let iv = &nonce[..NONCE_LENGTH];

                        let encrypted = encrypt(&ephemeral_sk, &pk, &msg, iv).map_err(|_| {
                            DispatchError::Other("ChainExtension failed to call ecies encrypt")
                        })?;

                        env.write(&encrypted.encode(), false, None).map_err(|_| {
                            DispatchError::Other("ChainExtension failed to return ecies result")
                        })?;

                        break;
                    }
                }
            }
        }
        Ok(RetVal::Converging(0))
    }
}
