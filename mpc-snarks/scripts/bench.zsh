#!/usr/bin/env zsh
trap "exit" INT TERM
trap "kill 0" EXIT

pkill proof || true

proof=$1
infra=$2
size=$3
n_parties=$4
if [[ -z $BIN ]]
then
    BIN=./target/release/proof
fi
if [[ -z $NETWORK_CONFIG ]]
then
    NETWORK_CONFIG=./data/$n_parties
fi
LABEL="timed section"


function usage {
  echo "Usage: $0 {groth16,marlin,plonk,marlin_mal,marlin_mal_rss_check} {hbc,spdz,gsz,rss3,local,ark-local} N_SQUARINGS N_PARTIES" >&2
  exit 1
}

if [ "$#" -ne 4 ] ; then
    usage
fi

case $proof in
    groth16|marlin|plonk|marlin_mal|marlin_mal_rss_check)
        ;;
    *)
        usage
esac

case $infra in
    hbc|spdz|gsz|rss3|local|ark-local)
        ;;
    *)
        usage
esac

sleep 1

case $infra in
    hbc|spdz|gsz|rss3)
        PROCS=()
        for i in $(seq 0 $(($n_parties - 1)))
        do
          #$BIN $i ./data/4 &
          if [ $i -eq 0 ]
          then
            RUST_LOG=debug RUST_BACKTRACE=1 $BIN -p $proof -c squaring --computation-size $size mpc --hosts $NETWORK_CONFIG --party $i --alg $infra | rg "End: *$LABEL" | rg -o '[0-9][0-9.]*.s' &
            pid=$!
          else
            RUST_LOG=debug $BIN -p $proof -c squaring --computation-size $size mpc --hosts $NETWORK_CONFIG --party $i --alg $infra > /dev/null &
            pid=$!
          fi
          PROCS+=($pid)
        done

        for pid in ${PROCS}
        do
          wait $pid
        done
    ;;
    local)
        $BIN -p $proof -c squaring --computation-size $size local | rg "End: *$LABEL" | rg -o '[0-9][0-9.]*.s'
    ;;
    ark-local)
        $BIN -p $proof -c squaring --computation-size $size ark-local | rg "End: *$LABEL" | rg -o '[0-9][0-9.]*.s'
    ;;
    *)
        usage
    ;;
esac

trap - INT TERM EXIT
