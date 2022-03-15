#!/bin/bash

command -v git || {
    echo "No git?"
    exit 1
}

version="$(git describe --always)"
echo -n "$version" | tee ./core/.version
