#!/usr/bin/env zsh
set -xe
trap "exit" INT TERM
trap "kill 0" EXIT

cargo +nightly build --example unit_test_rss3
BIN=./target/debug/examples/unit_test_rss3

RUST_BACKTRACE=1 RUST_LOG=debug $BIN 0 ./data/3 & ; pid0=$!
$BIN 1 ./data/3 & ; pid1=$!
$BIN 2 ./data/3 & ; pid2=$!

wait $pid0 $pid1 $pid2

echo done