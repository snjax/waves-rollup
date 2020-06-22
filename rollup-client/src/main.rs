#[macro_use] extern crate fawkes_crypto;
extern crate serde;

use clap::Clap;
use rollup_crypto::native::Tx;
use fawkes_crypto::native::bls12_381::Fr;
use fawkes_crypto::native::num::Num;
use rollup_crypto::ROLLUP_PARAMS;


#[derive(Clap)]
struct Opts {
    #[clap(subcommand)]
    command: SubCommand,
}


#[derive(Clap)]
enum SubCommand {
    /// Transfer assets from one cell to another
    Transfer(TransferOpts)
}


/// A subcommand for generating a SNARK proof
#[derive(Clap)]
struct TransferOpts {
    /// Leaf from index
    #[clap(short = "f", long = "from", default_value = "0")]
    from: u32,
    /// Leaf to index
    #[clap(short = "t", long = "to", default_value = "0")]
    to: u32,
    /// Amount
    #[clap(short = "a", long = "amount", default_value = "0")]
    amount: u64,
    /// Nonce
    #[clap(short = "n", long = "nonce", default_value = "0")]
    nonce: u64
}

fn main() {
    let opts: Opts = Opts::parse();
    match opts.command {
        SubCommand::Transfer(t) => {
            let mut tx = Tx::<Fr>{
                from: num!(t.from),
                to: num!(t.to),
                amount: num!(t.amount),
                nonce: num!(t.nonce),
                s: num!(0),
                r: num!(0)
            };
            let secret = Num::from_seed(format!("account{}", t.from).as_bytes());
            tx.sign(secret, &ROLLUP_PARAMS);
            let client = reqwest::blocking::Client::new();
            let resp = client.post("http://127.0.0.1:8000/post_tx").json(&tx).send();
            println!("{:?}", resp);
        }
    }
}
