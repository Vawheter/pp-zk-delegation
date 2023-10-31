#!/usr/bin/env zsh
set -xe
trap "exit" INT TERM
trap "kill 0" EXIT

cargo +nightly build --bin client_rss3 --release

BIN=./target/release/client_rss3

$BIN --rss3 --hosts data/3 -d sum 0 9 --party 0 & ; pid0=$!
$BIN --rss3 --hosts data/3 -d sum 1 0 --party 1 & ; pid1=$!
$BIN --rss3 --hosts data/3 -d sum 3 3 --party 2 & ; pid2=$!

wait $pid0 $pid1 $pid2

$BIN --rss3 --hosts data/3 -d product 4 2 --party 0 & ; pid0=$!
$BIN --rss3 --hosts data/3 -d product 7 1 --party 1 & ; pid1=$!
$BIN --rss3 --hosts data/3 -d product 3 2 --party 2 & ; pid2=$!

wait $pid0 $pid1 $pid2

# $BIN --rss3 --hosts data/3 -d pproduct 100 200 --party 0 & ; pid0=$!
# $BIN --rss3 --hosts data/3 -d pproduct 40 50 --party 1 & ; pid1=$!
# $BIN --rss3 --hosts data/3 -d pproduct 60 30 --party 2 & ; pid2=$!

# wait $pid0 $pid1 $pid2

# $BIN --rss3 --hosts data/3 -d polydiv 1 3 1 0 --party 0 & ; pid0=$!
# $BIN --rss3 --hosts data/3 -d polydiv 0 0 2 1 --party 1 & ; pid1=$!
# $BIN --rss3 --hosts data/3 -d polydiv 0 0 2 1 --party 2 & ; pid2=$!

# wait $pid0 $pid1 $pid2

# $BIN --rss3 --hosts data/3 -d dh 1 3 --party 0 & ; pid0=$!
# $BIN --rss3 --hosts data/3 -d dh 0 0 --party 1 & ; pid1=$!
# $BIN --rss3 --hosts data/3 -d dh 2 1 --party 2 & ; pid2=$!

# wait $pid0 $pid1 $pid2

# $BIN --rss3 --hosts data/3 -d groupops 1 3 --party 0 & ; pid0=$!
# $BIN --rss3 --hosts data/3 -d groupops 5 0 --party 1 & ; pid1=$!
# $BIN --rss3 --hosts data/3 -d groupops 4 2 --party 2 & ; pid2=$!

# wait $pid0 $pid1 $pid2

# # msm
# $BIN --hosts data/3 msm 4 1 2 --party 0 & ; pid0=$!
# $BIN --hosts data/3 msm 0 1 2 --party 1 & ; pid1=$!

# wait $pid0 $pid1 $pid2


# wait $pid0 $pid1

# $BIN --hosts data/3 -d product 1 0 --party 0 & ; pid0=$!
# $BIN --hosts data/3 -d product 0 1 --party 1 & ; pid1=$!

# wait $pid0 $pid1

# $BIN --hosts data/3 -d pproduct 2 3 --party 0 & ; pid0=$!
# $BIN --hosts data/3 -d pproduct 1 2 --party 1 & ; pid1=$!

# wait $pid0 $pid1

# # $BIN --hosts data/3 -d commit 1 0 --party 0 & ; pid0=$!
# # $BIN --hosts data/3 -d commit 0 1 --party 1 & ; pid1=$!
# # 
# # wait $pid0 $pid1
# # 
# # $BIN --hosts data/3 -d merkle 1 2 3 4 --party 0 & ; pid0=$!
# # $BIN --hosts data/3 -d merkle 0 0 0 0 --party 1 & ; pid1=$!
# # 
# # wait $pid0 $pid1
# # 
# # $BIN --hosts data/3 -d fri 2 2 1 7 --party 0 & ; pid0=$!
# # $BIN --hosts data/3 -d fri 0 0 0 0 --party 1 & ; pid1=$!
# # 
# # wait $pid0 $pid1

# # sum-check (G1)
# $BIN --hosts data/3 -d dh 0 4 6 --party 0 & ; pid0=$!
# $BIN --hosts data/3 -d dh 1 2 1 --party 1 & ; pid1=$!

# wait $pid0 $pid1

# # sum-check (G2)
# $BIN --hosts data/3 -d dh 0 4 6 --party 0 --use-g2 & ; pid0=$!
# $BIN --hosts data/3 -d dh 1 2 1 --party 1 --use-g2 & ; pid1=$!

# wait $pid0 $pid1

# # DDH triple check (pairing)
# $BIN --hosts data/3 -d pairingdh 0 1 6 --party 0 & ; pid0=$!
# $BIN --hosts data/3 -d pairingdh 2 2 0 --party 1 & ; pid1=$!

# wait $pid0 $pid1

# # lin-check (pairing)
# $BIN --hosts data/3 -d pairingprod 0 1 6 1 --party 0 & ; pid0=$!
# $BIN --hosts data/3 -d pairingprod 2 2 0 1 --party 1 & ; pid1=$!

# wait $pid0 $pid1

# # lin-check (pairing)
# $BIN --hosts data/3 -d pairingdiv 0 1 6 1 --party 0 & ; pid0=$!
# $BIN --hosts data/3 -d pairingdiv 2 2 0 1 --party 1 & ; pid1=$!

# wait $pid0 $pid1

# # groth16
# $BIN --hosts data/3 groth16 --party 0 & ; pid0=$!
# $BIN --hosts data/3 groth16 --party 1 & ; pid1=$!

# wait $pid0 $pid1

# # poly eval
# $BIN --hosts data/3 polyeval 1 2 --party 0 & ; pid0=$!
# $BIN --hosts data/3 polyeval 3 2 --party 1 & ; pid1=$!

# wait $pid0 $pid1

# # KZG commit (no blind)
# $BIN --hosts data/3 kzg 1 2 0 4 4 --party 0 & ; pid0=$!
# $BIN --hosts data/3 kzg 3 2 0 0 1 --party 1 & ; pid1=$!

# wait $pid0 $pid1

# # KZG commit (zk)
# $BIN --hosts data/3 kzgzk 1 2 0 4 4 --party 0 & ; pid0=$!
# $BIN --hosts data/3 kzgzk 3 2 0 0 1 --party 1 & ; pid1=$!

# wait $pid0 $pid1

# # KZG commit (zk, batch verify)
# $BIN --hosts data/3 kzgzkbatch 1 2 0 4 4 0 --party 0 & ; pid0=$!
# $BIN --hosts data/3 kzgzkbatch 3 2 0 0 1 0 --party 1 & ; pid1=$!

# wait $pid0 $pid1

# # poly commit
# $BIN --hosts data/3 marlinpc 0 0 --party 0 & ; pid0=$!
# $BIN --hosts data/3 marlinpc 0 0 --party 1 & ; pid1=$!

# wait $pid0 $pid1

# # marlin poly commit (zk, batch verify)
# $BIN --hosts data/3 marlinpcbatch 1 2 0 4 4 0 --party 0 & ; pid0=$!
# $BIN --hosts data/3 marlinpcbatch 3 2 0 0 1 0 --party 1 & ; pid1=$!

# wait $pid0 $pid1

# # plonk
# $BIN --hosts data/3 plonk --party 0 & ; pid0=$!
# $BIN --hosts data/3 plonk --party 1 & ; pid1=$!

# wait $pid0 $pid1

# # marlin
# $BIN --hosts data/3 marlin --party 0 & ; pid0=$!
# $BIN --hosts data/3 marlin --party 1 & ; pid1=$!

# wait $pid0 $pid1

trap - INT TERM EXIT

# ./bench_test.zsh
