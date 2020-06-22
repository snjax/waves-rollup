pub mod gen_test_data;

use fawkes_crypto::native::num::Num;
use fawkes_crypto::native::poseidon::{poseidon_with_salt, PoseidonParams, MerkleProof};
use fawkes_crypto::native::eddsaposeidon::{eddsaposeidon_verify, eddsaposeidon_sign};
use fawkes_crypto::core::field::Field;
use fawkes_crypto::core::sizedvec::SizedVec;
use fawkes_crypto::native::ecc::JubJubParams;

use typenum::Unsigned;
use std::fmt::Debug;
use std::marker::PhantomData;

use crate::constants::{SEED_TX_HASH, SEED_LEAF_HASH};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize="", deserialize=""))]
pub struct Leaf<F:Field> {
    pub owner: Num<F>,
    pub amount: Num<F>,
    pub nonce: Num<F>
}

impl<F:Field> Default for Leaf<F> {
    fn default() -> Self {
        Self {
            owner: num!(0),
            amount: num!(0),
            nonce: num!(0)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize="", deserialize=""))]
pub struct Tx<F:Field> {
    pub from: Num<F>,
    pub to: Num<F>,
    pub amount: Num<F>,
    pub nonce: Num<F>,
    pub s: Num<F>,
    pub r: Num<F>
}

impl<F:Field> Default for Tx<F> {
    fn default() -> Self {
        Self {
            from: num!(0),
            to: num!(0),
            amount: num!(0),
            nonce: num!(0),
            s: num!(0),
            r: num!(0)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize="", deserialize=""))]
pub struct TxEx<F:Field, L:Unsigned> {
    pub leaf_from: Leaf<F>,
    pub leaf_to: Leaf<F>,
    pub proof_from: MerkleProof<F, L>,
    pub proof_to: MerkleProof<F, L>
}

impl<F:Field, L:Unsigned> Default for TxEx<F,L> {
    fn default() -> Self {
        Self {
            leaf_from: Leaf::default(),
            leaf_to: Leaf::default(),
            proof_from: MerkleProof {
                sibling: SizedVec(vec![num!(0);L::USIZE], PhantomData),
                path: SizedVec(vec![false; L::USIZE], PhantomData)
            },
            proof_to: MerkleProof {
                sibling: SizedVec(vec![num!(0);L::USIZE], PhantomData),
                path: SizedVec(vec![false; L::USIZE], PhantomData)
            }
        }
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize="", deserialize=""))]
pub struct RollupPub<F:Field> {
    pub root_before: Num<F>,
    pub root_after: Num<F>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize="", deserialize=""))]
pub struct RollupSec<F:Field, L:Unsigned, N:Unsigned> {
    pub tx: SizedVec<Tx<F>, N>,
    pub txex: SizedVec<TxEx<F, L>, N>
}



impl<F:Field> Leaf<F> {
    pub fn hash<J:JubJubParams<Fr=F>>(&self, params:&RollupParams<F, J>) -> Num<F> {
        poseidon_with_salt(&[self.owner.clone(), self.amount.clone(), self.nonce.clone()], SEED_LEAF_HASH, &params.leaf)
    }
}


impl<F:Field> Tx<F> {
    pub fn hash<J:JubJubParams<Fr=F>>(&self, params:&RollupParams<F, J>) -> Num<F> {
        poseidon_with_salt(&[self.from.clone(), self.to.clone(), self.amount.clone(), self.nonce.clone()], SEED_TX_HASH, &params.tx)
    }

    pub fn sigverify<J:JubJubParams<Fr=F>>(&self, owner: Num<F>, params:&RollupParams<F, J>) -> bool {
        let m = self.hash(params);
        eddsaposeidon_verify(self.s.into_other(), self.r, owner, m, &params.sign, &params.jubjub_params)
    }

    pub fn sign<J:JubJubParams<Fr=F>>(&mut self, secret: Num<J::Fs>, params:&RollupParams<F, J>) {
        let (s, r) = eddsaposeidon_sign(secret, self.hash(params), &params.sign, &params.jubjub_params);
        self.s = s.into_other();
        self.r = r;
    }
}




pub struct RollupParams<F:Field, J:JubJubParams<Fr=F>> {
    pub compress : PoseidonParams<F>,
    pub leaf : PoseidonParams<F>,
    pub tx : PoseidonParams<F>,
    pub sign : PoseidonParams<F>,
    pub jubjub_params: J
}