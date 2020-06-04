#[macro_use]
extern crate fawkes_crypto;

#[macro_use]
extern crate fawkes_crypto_derive;

#[macro_use]
extern crate serde;

pub mod circuit;
pub mod native;
pub mod constants;



use crate::{
    circuit::{CRollupPub, CRollupSec, c_rollup},
    native::{RollupPub, RollupSec, RollupParams, gen_test_data::gen_test_data}
};

use typenum::{U16, U2};
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







groth16_waves_bindings!(cli, RollupPub<Fr>, CRollupPub, RollupSec<Fr, U16, U2>, CRollupSec, ROLLUP_PARAMS, c_rollup, gen_test_data);

fn main() {
    cli::cli_main()
}