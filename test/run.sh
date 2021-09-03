#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o xtrace

DOCKER_NETWORK=mymacvlan
HOST_IP=`hostname -I | cut -d ' ' -f 1`
LINK_DEV_IP="10.1.1.15"
LINK_DEV_NAME=mylink
CONTAINER_NET="10.1.1.0/24"
CONTAINER_SERVER_IP="10.1.1.48"
CONTAINER_CLIENT_IP="10.1.1.64"
CONTAINER_IP="10.1.1.48"
GRPC_PORT="9000"

# Create MacVLAN network for container to assign static IP
docker network create -d macvlan --subnet=$CONTAINER_NET --ip-range=$CONTAINER_NET -o macvlan_mode=bridge -o parent=eth0 $DOCKER_NETWORK
# Make host and container accessible
# https://rehtt.com/index.php/archives/236/
sudo ip link add $LINK_DEV_NAME link eth0 type macvlan mode bridge
sudo ip addr add $LINK_DEV_IP dev $LINK_DEV_NAME
sudo ip link set $LINK_DEV_NAME up
sudo ip route add ${CONTAINER_NET} dev $LINK_DEV_NAME

cd src

docker kill `docker ps -a -q` || true # Clean all pending containers to release IP
docker run --rm -d -v `pwd`:`pwd` -w `pwd` --net=mymacvlan --ip=$CONTAINER_SERVER_IP --name exch_server python:3 python3 exch_server.py
sleep 1 # Wait a while for server to ready
docker run --rm -v `pwd`:`pwd` -w `pwd` --net=mymacvlan --ip=$CONTAINER_CLIENT_IP --name exch_client python:3 python3 exch_client.py -s $CONTAINER_SERVER_IP

cd ../scapy
cp ../src/roce*.py .
cp ../src/sim_*.py .
cp ../src/test_*.py .
sleep 1 # Wait a while for docker to release IP
docker run --rm -d -v `pwd`:`pwd` -w `pwd` --net=mymacvlan --ip=$CONTAINER_SERVER_IP --name test_server python:3 python3 test_server.py -s $CONTAINER_SERVER_IP
sleep 1 # Wait a while for server to ready
docker run --rm -v `pwd`:`pwd` -w `pwd` --net=mymacvlan --ip=$CONTAINER_CLIENT_IP --name test_client python:3 python3 test_client.py -d $CONTAINER_SERVER_IP -s $CONTAINER_CLIENT_IP

sleep 1 # Wait a while for docker to release IP
docker run --rm -d -v `pwd`:`pwd` -w `pwd` --net=mymacvlan --ip=$CONTAINER_SERVER_IP --name sim_server python:3 python3 sim_server.py -s $CONTAINER_SERVER_IP
sleep 1 # Wait a while for server to ready
docker run --rm -v `pwd`:`pwd` -w `pwd` --net=mymacvlan --ip=$CONTAINER_CLIENT_IP --name sim_client python:3 python3 sim_client.py -d $CONTAINER_SERVER_IP -s $CONTAINER_CLIENT_IP


# Start Sanity Test
cd ../test
sleep 1 # Wait the previous test finished
sed -i "s/SIDE_2_IP/${CONTAINER_IP}/g" ./case.yaml
sed -i "s/SIDE_1_IP/${LINK_DEV_IP}/g" ./case.yaml
sed -i "s/SIDE_1_PORT/${GRPC_PORT}/g" ./case.yaml
sed -i "s/SIDE_2_PORT/${GRPC_PORT}/g" ./case.yaml

# Start Rust Side
cd ../

## Remove existing devices if any
RXE_DEV=rxe_eth0
sudo rdma link delete $RXE_DEV || true

ETH_DEV=`ifconfig -s | grep '^e' | cut -d ' ' -f 1 | head -n 1`
sudo rdma link add $RXE_DEV type rxe netdev ${LINK_DEV_NAME}

./target/debug/sanity_side ${GRPC_PORT} 2>&1 > ./rust_side.log &

# Start Python Side
cd ./src
docker run --rm -d -v `pwd`:`pwd` -w `pwd` --net=${DOCKER_NETWORK} --ip=${CONTAINER_IP} --name python_side grpc-python3 python3 sanity_side.py ${CONTAINER_IP} ${GRPC_PORT}
docker logs -f python_side > ../python_side.log &

# Wait a while to Start Manager Python
sleep 2
python3 ./sanity_manager.py ../test/case.yaml
