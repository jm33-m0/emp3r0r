#!/bin/bash

cd src/Remote
ls | while read dir; do
    if [[ -d $dir ]]; then
        cd $dir
        if [[ -f "Makefile" ]]; then
            make 1>/dev/null
            echo "- $dir"
        fi
        cd ..
    fi
done
cd ../..

cd src/Injection
ls | while read dir; do
    if [[ -d $dir ]]; then
        cd $dir
        if [[ -f "Makefile" ]]; then
            make 1>/dev/null
            echo "- $dir"
        fi
        cd ..
    fi
done
cd ../..

