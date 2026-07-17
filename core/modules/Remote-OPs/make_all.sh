#!/bin/bash

# Remove mkdir and mv lines from all Makefiles to keep object files in their source directories
find src -name Makefile -exec sed -i '/mkdir -p/d; /mv $(BOFNAME)\*\.o/d; /mv .* \.\.\//d' {} +

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

