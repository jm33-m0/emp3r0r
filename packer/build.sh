#!/bin/bash

go mod tidy
(
    cd ./cmd/cryptor/ || exit 1
    go build -o cryptor.exe &&
        mv ./cryptor.exe ../../
)

echo "run cryptor.exe"
