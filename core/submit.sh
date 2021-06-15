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
    git status
    exit
fi

yes_no "[?] Add new tag" && (
    read -r -p "[?] Enter new version tag: " tag
    echo -n "v$tag" >.version
    git commit .version -S -m "bump version to $tag"
    git add .version
    git tag "v$tag" -a -m "v$tag"
)

git push
git push origin --tags
