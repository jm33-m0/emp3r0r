#!/bin/bash

command -v git || {
    echo "No git?"
    exit 1
}

version="$(git describe --tags)"
echo -n "$version" | tee ./core/.version || {
    echo "Failed to write version string"
    exit 2
}
