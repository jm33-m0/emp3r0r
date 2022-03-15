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

# commit
git config user.name "GitHub Actions Bot"
git config user.email "<>"
git add .
git commit -a -m "version string written by Github Actions Bot"
git push
