use fawkes_crypto::native::bls12_381::{Fr, Fs};
use fawkes_crypto::native::ecc::JubJubParams;
use fawkes_crypto::native::num::Num;
use fawkes_crypto::core::sizedvec::SizedVec;
use fawkes_crypto::native::poseidon::{poseidon, MerkleProof};
use fawkes_crypto::native::eddsaposeidon::eddsaposeidon_sign;
use num::bigint::{BigUint};
use std::marker::PhantomData;
use typenum::Unsigned;

use crate::{
    native::{RollupPub, RollupSec, Leaf, Tx, TxEx}
};

use crate::ROLLUP_PARAMS;
use rand::{Rng, thread_rng};



pub struct RollupState<L:Unsigned, N:Unsigned>{
    pub leaf:Vec<Leaf<Fr>>,
    pub cell: Vec<Num<Fr>>,
    pub phantom: PhantomData<(L,N)>
}

impl<L:Unsigned, N:Unsigned> RollupState<L,N> {
    pub fn new() -> Self {
        Self::from_leaf(&vec![Leaf{owner:num!(0), amount:num!(0), nonce:num!(0)}; 1<<L::USIZE])
    }

    pub fn root(&self) -> Num<Fr> {
        self.cell[0]
    }

    pub fn from_leaf(leaf:&[Leaf<Fr>]) -> Self {
        let n = leaf.len();
        let mut cell = vec![num!(0); 2*n-1];
        for i in 0..n {
            cell[i+n-1] = leaf[i].hash(&ROLLUP_PARAMS);
        }

        for i in (0..n-1).rev() {
            cell[i] = poseidon(&[cell[2*i+1], cell[2*i+2]], &ROLLUP_PARAMS.compress);
        }
        Self{leaf:leaf.to_vec(), cell, phantom:PhantomData}
    }

    pub fn update(&mut self, i:usize) {
        let n = self.leaf.len();
        self.cell[i+n-1] = self.leaf[i].hash(&ROLLUP_PARAMS);
        for k in 1..L::USIZE+1 {
            let i = (i>>k) + (n>>k) - 1;
            self.cell[i] = poseidon(&[self.cell[2*i+1], self.cell[2*i+2]], &ROLLUP_PARAMS.compress);
        }
    }

    pub fn proof(&self, i:usize) -> MerkleProof<Fr, L> {
        let n = self.leaf.len();
        let sibling = (0..L::USIZE).map(|k| self.cell[((n>>k)+(i>>k)^1)-1]).collect();
        let path = (0..L::USIZE).map(|k| (i>>k)&1==1).collect();
        MerkleProof {sibling, path}
    }

    pub fn transact(&mut self, tx:&Tx<Fr>) -> Option<TxEx<Fr, L>> {
        let from = Into::<u64>::into(tx.from) as usize;
        let to = Into::<u64>::into(tx.to) as usize;
        if self.leaf[from].nonce!=tx.nonce {
            None
        } else if !tx.sigverify(self.leaf[from].owner, &ROLLUP_PARAMS) {
            None
        } else if Into::<BigUint>::into(self.leaf[from].amount) < Into::<BigUint>::into(tx.amount) {
            None
        } else {
            let leaf_from = self.leaf[from].clone();
            let leaf_to = self.leaf[to].clone();

            let proof_from = self.proof(from);
            self.leaf[from].amount -= tx.amount;
            self.leaf[from].nonce += num!(1);
            self.update(from);

            let proof_to = self.proof(to);
            self.leaf[to].amount += tx.amount;
            self.update(to);
            Some(TxEx{leaf_from, leaf_to, proof_from, proof_to})
        }
    }

    pub fn block(&mut self, tx:&[Tx<Fr>]) -> Option<(RollupPub<Fr>, RollupSec<Fr, L, N>)> {
        assert!(tx.len()==N::USIZE);
        let root_before = self.cell[0].clone();
        let tx = SizedVec(tx.to_vec(), PhantomData);
        let txex = tx.iter().map(|t| self.transact(t)).collect::<Option<SizedVec<_, _>>>()?;
        let root_after = self.cell[0].clone();

        Some((RollupPub{root_before, root_after}, RollupSec{tx, txex}))
    }


}



pub fn gen_test_data<L:Unsigned, N:Unsigned>() -> (RollupPub<Fr>, RollupSec<Fr, L, N>) {
    let mut rng = thread_rng();


    let proof_len = L::USIZE;
    let leaf_len = 1<<proof_len as usize;
    let tx_len = N::USIZE;

    let sk = (0..leaf_len).map(|_| rng.gen()).collect::<Vec<Num<Fs>>>();

    let mut leaf = (0..leaf_len).map(|i| Leaf::<Fr> {
        owner: ROLLUP_PARAMS.jubjub_params.edwards_g().mul(sk[i], &ROLLUP_PARAMS.jubjub_params).x,
        amount: num!(rng.gen::<u32>()),
        nonce: num!(0)
    }).collect::<Vec<_>>();

    let mut state = RollupState::from_leaf(&leaf);

    let tx = (0..tx_len).map(|_| {
        let from = rng.gen::<usize>() % leaf_len;
        let mut to = rng.gen::<usize>() % (leaf_len-1);
        if to >= from {
            to += 1;
        }

        let amount = if leaf[from].amount.is_zero() {
            num!(0)
        } else {
            num!(rng.gen::<u64>() % Into::<u64>::into(leaf[from].amount)) 
        };

        let mut tx = Tx {
            from: num!(from as u64),
            to: num!(to  as u64),
            amount: amount,
            nonce: leaf[from].nonce,
            s: num!(0),
            r: num!(0)
        };


        let (s, r) = eddsaposeidon_sign(sk[from], tx.hash(&ROLLUP_PARAMS), &ROLLUP_PARAMS.sign, &ROLLUP_PARAMS.jubjub_params);
        tx.s = s.into_other();
        tx.r = r;
        

        leaf[from].nonce += num!(1);
        leaf[from].amount -= amount;
        leaf[to].amount += amount;

        tx
    }).collect::<Vec<_>>();

    state.block(&tx).unwrap()

}


#[cfg(test)]
mod rollup_test {
    use super::*;
    use crate::{L, N};
    use crate::circuit::{c_rollup, CRollupPub, CRollupSec};
    use fawkes_crypto::core::cs::TestCS;
    use fawkes_crypto::core::signal::Signal;
    use std::time::{Instant};

    #[test]
    fn test_rollup() {

        let (p, s) = gen_test_data::<L, N>();

        
        let ref mut cs = TestCS::<Fr>::new();
        let signal_p = CRollupPub::alloc(cs, Some(&p));
        let signal_s = CRollupSec::alloc(cs, Some(&s));


        let mut n_constraints = cs.num_constraints();
        let start = Instant::now();
        c_rollup(&signal_p, &signal_s, &ROLLUP_PARAMS);
        let duration = start.elapsed();
        n_constraints=cs.num_constraints()-n_constraints;
        
        println!("rollup constraints = {}", n_constraints);
        println!("circuit building time = {} sec", duration.as_secs_f32());

    }

}