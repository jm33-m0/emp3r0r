#!/bin/bash

yes_no() {
    while true; do
        read -r -p "$* [y/n]: " yn
        case $yn in
        [Yy]*) return 0 ;;
        [Nn]*)
            echo "Aborted"
            return 1
            ;;
        esac
    done
}

if [[ $(git status --porcelain) ]]; then
    echo "[-] Commit and push your work before using this script"
    lazygit
fi

yes_no "[?] Add new tag" && (
    read -r -p "[?] Enter new version tag: " tag
    git tag "v$tag" -a -m "v$tag"
)

version=$(git describe --tags || git describe --always)
echo "$version" >.version
git add .version
git commit .version -m "bump version to $version"
git push origin --tags
