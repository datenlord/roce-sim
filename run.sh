#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o xtrace

DOCKER_NETWORK=mymacvlan
HOST_IP=`hostname -I | cut -d ' ' -f 1`
LINK_DEV_IP="10.1.1.15"
LINK_DEV_NAME=mylink
CONTAINER_NET="10.1.1.0/16"
CONTAINER_IP="10.1.1.48"

# Create MacVLAN network for container to assign static IP
docker network create -d macvlan --subnet=$CONTAINER_NET --ip-range=$CONTAINER_NET -o macvlan_mode=bridge -o parent=eth0 $DOCKER_NETWORK
# Make host and container accessible
# https://rehtt.com/index.php/archives/236/
sudo ip link add $LINK_DEV_NAME link eth0 type macvlan mode bridge
sudo ip addr add $LINK_DEV_IP dev $LINK_DEV_NAME
sudo ip link set $LINK_DEV_NAME up
sudo ip route add $CONTAINER_IP dev $LINK_DEV_NAME

cd src
docker run --rm -d -v `pwd`:`pwd` -w `pwd` --net=mymacvlan --ip=$CONTAINER_IP --name exch_server python python3 exch_server.py
sleep 1 # Wait a while for server to ready
python3 exch_client.py -s $CONTAINER_IP

cd ../scapy
cp ../src/roce*.py .
cp ../src/test_*.py .
sleep 1 # Wait a while for docker to release CONTAINER_IP
docker run --rm -d -v `pwd`:`pwd` -w `pwd` --net=mymacvlan --ip=$CONTAINER_IP --name test_server python python3 test_server.py -s $CONTAINER_IP
sleep 1 # Wait a while for server to ready
sudo python3 test_client.py -d $CONTAINER_IP -s $HOST_IP
