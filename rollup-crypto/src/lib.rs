#[macro_use]
extern crate fawkes_crypto;

#[macro_use]
extern crate fawkes_crypto_derive;

#[macro_use]
extern crate serde;

pub mod circuit;
pub mod native;
pub mod constants;

use typenum::{U16};
pub type L = U16;
pub type N = U16;

use crate::native::RollupParams;
use fawkes_crypto::native::bls12_381::Fr;

use fawkes_crypto::native::poseidon::PoseidonParams;
use fawkes_crypto::native::bls12_381::JubJubBLS12_381;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref ROLLUP_PARAMS: RollupParams<Fr, JubJubBLS12_381> = RollupParams {
        compress : PoseidonParams::<Fr>::new(3, 8, 53),
        leaf : PoseidonParams::<Fr>::new(4, 8, 53),
        tx : PoseidonParams::<Fr>::new(5, 8, 54),
        sign : PoseidonParams::<Fr>::new(4, 8, 54),
        jubjub_params: JubJubBLS12_381::new()
    };
}


