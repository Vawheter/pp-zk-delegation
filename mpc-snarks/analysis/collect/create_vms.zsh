#!/usr/bin/env zsh
trap "exit" INT TERM
trap "kill 0" EXIT

set -xe

n=$1
cores=$2

IMAGE='with-kill'

function usage {
  echo "Usage: $0 N_VMS CORES" >&2
  exit 1
}

if [ "$#" -ne 2 ] ; then
    usage
fi

VM_FILE=vms
HOSTS_FILE=hosts

rm -f $VM_FILE
rm -f $HOSTS_FILE
touch $VM_FILE
touch $HOSTS_FILE

names=$(for i in $(seq 1 $n); do; echo -n "vm-$i "; done)



gcloud beta compute instances create $=names \
    --zone us-central1-a \
    --project soe-collaborative-proof \
    --image-project soe-collaborative-proof \
    --image $IMAGE \
    --machine-type=n2-standard-$((2 * $cores))
for name in $=names
do
  echo $name >> $VM_FILE
done

echo letting them start up
sleep 60

for name in $=names
do
  pubip=$(gcloud compute instances describe $name --format='get(networkInterfaces[0].accessConfigs[0].natIP)'\
      --zone us-central1-a \
      --project soe-collaborative-proof)
  privip=$(gcloud compute instances describe $name --format='get(networkInterfaces[0].networkIP)'\
      --zone us-central1-a \
      --project soe-collaborative-proof)
  echo $pubip $privip >> $HOSTS_FILE
  #ssh-keyscan $ip >> ~/.ssh/known_hosts
  ssh-keygen -R $pubip
  ssh -o "StrictHostKeyChecking accept-new" $pubip 'sudo ./hyperthreading.sh -d'
done

# gcloud beta compute instances delete $name \
#     --zone us-central1-a \
#     --project soe-collaborative-proof


trap - INT TERM EXIT
