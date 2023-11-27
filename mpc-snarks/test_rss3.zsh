set -xe

cargo +nightly build --bin proof

BIN=./target/debug/proof

# BIN=$BIN ./scripts/bench.zsh groth16 rss3 10 3

# BIN=$BIN ./scripts/bench.zsh marlin rss3 5 3

BIN=$BIN ./scripts/bench.zsh plonk rss3 1000 3
# BIN=$BIN ./scripts/bench.zsh plonk spdz 10 3
# BIN=$BIN ./scripts/bench.zsh plonk gsz20 10 3
