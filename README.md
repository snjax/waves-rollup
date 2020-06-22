# zkRollup prototype

## Build solution

```
cargo build --release
cd rollup-node
npm i
cd ..
./tagret/rollup-prover/setup
```

## Deploy

Set `rollup-node/.env`

```
WAVES_RPC=https://nodes-stagenet.wavesnodes.com/

WAVES_CHAINID=S
MNEMONIC=testacc2
DAPP=S8iUuoaoAb1L7doUHQj4wrD6BKWanpWaJ6Wn2yxaAX4
```

Run `deploy.sh`

## Commands

### Start rollup server

```
./target/release/rollup-server
```

### Get state of account

```
curl http://127.0.0.1:8000/leaf/<leaf index>
```

### Transfer asset to another account

```
./target/release/rollup-client transfer -f <account number from> -t <account number to> -n <nonce> -a <amount>
```

### Publish block

`publish_block.sh`