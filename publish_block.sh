curl -X POST http://127.0.0.1:8000/publish_block
./target/release/rollup-prover prove
cd rollup-node
node publish_block.js
cd ..

