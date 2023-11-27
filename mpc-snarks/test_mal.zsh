set -xe

cargo +nightly build --bin proof

BIN=./target/debug/proof

BIN=$BIN ./scripts/bench.zsh marlin_mal hbc 10 3
BIN=$BIN ./scripts/bench.zsh marlin_mal spdz 10 3
BIN=$BIN ./scripts/bench.zsh marlin_mal gsz 10 3
BIN=$BIN ./scripts/bench.zsh marlin_mal rss3 10 3

