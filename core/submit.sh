#!/bin/bash

version=$(git describe --tags || git describe --always)
echo "$version" >.version
git add .version
git commit .version -m "bump version to $version"
git push
