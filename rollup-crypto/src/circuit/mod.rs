use fawkes_crypto::circuit::num::CNum;
use fawkes_crypto::circuit::bool::CBool;
use fawkes_crypto::circuit::poseidon::{CMerkleProof, c_poseidon_with_salt, c_poseidon_merkle_proof_root};
use fawkes_crypto::circuit::eddsaposeidon::c_eddsaposeidon_verify;
use fawkes_crypto::circuit::bitify::c_into_bits_le;
use fawkes_crypto::core::signal::Signal;
use fawkes_crypto::core::cs::ConstraintSystem;
use fawkes_crypto::core::sizedvec::SizedVec;
use fawkes_crypto::native::ecc::JubJubParams;
use typenum::Unsigned;

use crate::native::{RollupPub, RollupSec, Leaf, Tx, TxEx, RollupParams};
use crate::constants::{AMOUNT_LENGTH, SEED_TX_HASH, SEED_LEAF_HASH};

#[derive(Clone, Signal)]
#[Value="Leaf<CS::F>"]
pub struct CLeaf<'a, CS:ConstraintSystem> {
    pub owner: CNum<'a, CS>,
    pub amount: CNum<'a, CS>,
    pub nonce: CNum<'a, CS>
}

impl<'a, CS:ConstraintSystem> CLeaf<'a, CS> {
    pub fn hash<J:JubJubParams<Fr=CS::F>>(&self, params:&RollupParams<CS::F, J>) -> CNum<'a, CS> {
        c_poseidon_with_salt(&[self.owner.clone(), self.amount.clone(), self.nonce.clone()], SEED_LEAF_HASH, &params.leaf)
    }
}

#[derive(Clone, Signal)]
#[Value="Tx<CS::F>"]
pub struct CTx<'a, CS:ConstraintSystem> {
    pub from: CNum<'a, CS>,
    pub to: CNum<'a, CS>,
    pub amount: CNum<'a, CS>,
    pub nonce: CNum<'a, CS>,
    pub s: CNum<'a, CS>,
    pub r: CNum<'a, CS>
}

impl<'a, CS:ConstraintSystem> CTx<'a, CS> {
    pub fn hash<J:JubJubParams<Fr=CS::F>>(&self, params:&RollupParams<CS::F, J>) -> CNum<'a, CS> {
        c_poseidon_with_salt(&[self.from.clone(), self.to.clone(), self.amount.clone(), self.nonce.clone()], SEED_TX_HASH, &params.tx)
    }

    pub fn sigverify<J:JubJubParams<Fr=CS::F>>(&self, owner: &CNum<'a,CS>, params:&RollupParams<CS::F, J>) -> CBool<'a, CS> {
        let ref m = self.hash(params);
        c_eddsaposeidon_verify(&self.s, &self.r, owner, m, &params.sign, &params.jubjub_params)
    }
}

#[derive(Clone, Signal)]
#[Value="TxEx<CS::F, L>"]
pub struct CTxEx<'a, CS:ConstraintSystem, L:Unsigned> {
    pub leaf_from: CLeaf<'a, CS>,
    pub leaf_to: CLeaf<'a, CS>,
    pub proof_from: CMerkleProof<'a, CS, L>,
    pub proof_to: CMerkleProof<'a, CS, L>
}


#[derive(Clone, Signal)]
#[Value="RollupPub<CS::F>"]
pub struct CRollupPub<'a, CS:ConstraintSystem> {
    pub root_before: CNum<'a, CS>,
    pub root_after: CNum<'a, CS>
}

#[derive(Clone, Signal)]
#[Value="RollupSec<CS::F, L, N>"]
pub struct CRollupSec<'a, CS:ConstraintSystem, L:Unsigned, N:Unsigned> {
    pub tx: SizedVec<CTx<'a, CS>, N>,
    pub txex: SizedVec<CTxEx<'a, CS, L>, N>
}


pub fn c_rollup<'a, CS:ConstraintSystem, L:Unsigned, N:Unsigned, J:JubJubParams<Fr=CS::F>>
    (p: &CRollupPub<'a, CS>, s:&CRollupSec<'a, CS, L, N>, params:&RollupParams<CS::F, J>)
{
    for t in s.txex.iter() {
        t.proof_to.path.iter().for_each(|bit| bit.assert());
        t.proof_from.path.iter().for_each(|bit| bit.assert());
    }

    let mut cur_root = p.root_before.clone();
    for i in 0..N::USIZE {
        let ref tx = s.tx[i];
        let ref notempty = num!(1) - tx.amount.is_zero().0;
        let ref selftx = (&tx.from - &tx.to).is_zero().0;
        (num!(2) - notempty - selftx).assert_nonzero();

        let  CTxEx {mut leaf_from, mut leaf_to, proof_from, proof_to} = s.txex[i].clone();
        
        ((&leaf_from.nonce - &tx.nonce) * notempty).assert_zero();
        ((tx.sigverify(&leaf_from.owner, params).0 - num!(1)) * notempty).assert_zero();

        let cmp_root = c_poseidon_merkle_proof_root(&leaf_from.hash(params), &proof_from, &params.compress);
        
        ((cmp_root - &cur_root) * notempty).assert_zero();
        
        leaf_from.amount -= &tx.amount;
        leaf_from.nonce += num!(1);
        c_into_bits_le(&leaf_from.amount, AMOUNT_LENGTH);
        cur_root += (c_poseidon_merkle_proof_root(&leaf_from.hash(params), &proof_from, &params.compress) - &cur_root) * notempty;

        let cmp_root = c_poseidon_merkle_proof_root(&leaf_to.hash(params), &proof_to, &params.compress);
        
        ((cmp_root - &cur_root) * notempty).assert_zero();
        leaf_to.amount += &tx.amount;
        c_into_bits_le(&leaf_to.amount, AMOUNT_LENGTH);   
        cur_root += (c_poseidon_merkle_proof_root(&leaf_to.hash(params), &proof_to, &params.compress) - &cur_root) * notempty;
    }

    (cur_root - &p.root_after).assert_zero();


    

}