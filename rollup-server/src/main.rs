#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
#[macro_use] extern crate fawkes_crypto;

use rocket_contrib::json::Json;



use fawkes_crypto::native::bls12_381::{Fr};
use fawkes_crypto::native::ecc::JubJubParams;
use fawkes_crypto::native::num::Num;
use fawkes_crypto::core::sizedvec::SizedVec;
use std::marker::PhantomData;
use rollup_crypto::{
    native::{RollupPub, RollupSec, Leaf, Tx, TxEx},
    native::gen_test_data::RollupState
};

use rollup_crypto::ROLLUP_PARAMS;
use lazy_static::lazy_static;
use std::sync::{Mutex, Arc};
use typenum::{Unsigned};

use rollup_crypto::{L, N};


struct AppState<L:Unsigned, N:Unsigned> {
    pub rollup: RollupState<L, N>,
    pub pending_tx: Vec<Tx<Fr>>,
    pub pending_tx_ex: Vec<TxEx<Fr, L>>,
    pub root_before: Num<Fr>,
}


lazy_static!{
    static ref STATE: Arc<Mutex<AppState<L, N>>> = {
        let mut rollup = RollupState::new();
        
        // genesis state
        for i in 0..10 {
            let secret = Num::from_seed(format!("account{}", i).as_bytes());
            let amount = num!(1_000_000);
            let owner = ROLLUP_PARAMS.jubjub_params.edwards_g().mul(secret, &ROLLUP_PARAMS.jubjub_params).x;
            rollup.leaf[i] = Leaf {
                owner,
                amount,
                nonce: num!(0)
            };
            rollup.update(i);
        }
        let root_before = rollup.cell[0];

        Arc::new(Mutex::new(AppState{
            rollup,
            pending_tx: vec![],
            pending_tx_ex: vec![],
            root_before
        }))
    };
}

#[post("/post_tx", format="json", data="<tx>")]
fn post_tx(tx: Json<Tx<Fr>>) -> Option<()> {
    let mut state = STATE.lock().ok()?;
    if state.pending_tx.len() > N::USIZE {
        None 
    } else {
        let tx = tx.into_inner();
        let tx_ex = state.rollup.transact(&tx)?;
        state.pending_tx.push(tx);
        state.pending_tx_ex.push(tx_ex);
        Some(())
    }
}



#[post("/publish_block")]
fn publish_block() -> Option<()> {
    let mut state = STATE.lock().ok()?;

    let tx = SizedVec(state.pending_tx.iter().cloned().chain(std::iter::repeat(Tx::default())).take(N::USIZE).collect(),  PhantomData);
    let txex = SizedVec(state.pending_tx_ex.iter().cloned().chain(std::iter::repeat(TxEx::default())).take(N::USIZE).collect(),  PhantomData);

    let result  = (
        RollupPub {root_before: state.root_before, root_after: state.rollup.cell[0]},
        RollupSec::<_, L, N> {tx, txex}
    );


    let data_str = serde_json::to_string_pretty(&result).unwrap();
    std::fs::write("object.json", &data_str.into_bytes()).unwrap();
    state.root_before = state.rollup.cell[0];
    state.pending_tx = vec![];
    state.pending_tx_ex = vec![];

    Some(())
}

#[get("/leaf/<id>")]
fn get_leaf(id: usize) -> Option<Json<Leaf<Fr>>> {
    if 1<<L::USIZE <= id {
        None
    } else {
        let state = STATE.lock().ok()?;
        Some(Json(state.rollup.leaf[id].clone()))
    }
}



fn main() {
    rocket::ignite().mount("/", routes![get_leaf, post_tx, publish_block]).launch();
}




