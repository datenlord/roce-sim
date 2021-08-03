#!/bin/sh

#python -m grpc_tools.protoc -I ./src/proto/ --python_out=./src/proto_out/ --grpc_python_out=./src/proto_out/ ./src/proto/*.proto
python -m grpc_tools.protoc -I ./src/ --python_out=./src/ --grpc_python_out=./src/ ./src/proto/*.proto
