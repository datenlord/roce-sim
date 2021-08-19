#!/bin/sh

python3 -m grpc_tools.protoc -I ./src/ --python_out=./src/ --grpc_python_out=./src/ ./src/proto/*.proto
protoc --rust_out=./src/proto/ --grpc_out=./src/proto/ -I ./src/ --plugin=protoc-gen-grpc=`which grpc_rust_plugin` ./src/proto/*.proto
