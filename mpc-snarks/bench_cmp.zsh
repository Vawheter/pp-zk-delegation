set -xe

cargo +nightly build --bin proof --release

BIN=./target/release/proof

# BIN=$BIN ./scripts/bench.zsh groth16 local 10000 3
# BIN=$BIN ./scripts/bench.zsh groth16 ark-local 10000 3
# BIN=$BIN ./scripts/bench.zsh groth16 hbc 10000 3
# BIN=$BIN ./scripts/bench.zsh groth16 spdz 10000 3
# BIN=$BIN ./scripts/bench.zsh groth16 gsz 10000 3
# BIN=$BIN ./scripts/bench.zsh groth16 rss3 10000 3

# BIN=$BIN ./scripts/bench.zsh marlin local 10000 3
# BIN=$BIN ./scripts/bench.zsh marlin ark-local 10000 3
# BIN=$BIN ./scripts/bench.zsh marlin hbc 10000 3
# BIN=$BIN ./scripts/bench.zsh marlin spdz 10000 3
# BIN=$BIN ./scripts/bench.zsh marlin gsz 10000 3
# BIN=$BIN ./scripts/bench.zsh marlin rss3 10000 3

# BIN=$BIN ./scripts/bench.zsh plonk local 10000 3
# BIN=$BIN ./scripts/bench.zsh plonk ark-local 10000 3
# BIN=$BIN ./scripts/bench.zsh plonk hbc 10000 3
BIN=$BIN ./scripts/bench.zsh plonk spdz 10000 3
BIN=$BIN ./scripts/bench.zsh plonk gsz 10000 3
BIN=$BIN ./scripts/bench.zsh plonk rss3 10000 3
