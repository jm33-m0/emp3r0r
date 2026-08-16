#!/bin/bash

cd ./src/SA/$1
make
VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "0.0.0-dev")

# Check extension.json for required fields (supports both V1 and V2 manifests)
# V1: fields at top level
# V2: fields inside commands[0]

HELP=$(cat extension.json | jq -M '.help // .commands[0].help')
if [ "null" = "$HELP" ]; then
    echo "WARN: $1 extension.json is missing 'help' property"
    exit 1
fi
NAME=$(cat extension.json | jq -M .name)
if [ "null" = "$NAME" ]; then
    echo "WARN: $1 extension.json is missing 'name' property"
    exit 1
fi
CMD_NAME=$(cat extension.json | jq -M '.command_name // .commands[0].command_name')
if [ "null" = "$CMD_NAME" ]; then
    echo "WARN: $1 extension.json is missing 'command_name' property"
    exit 1
fi
ENTRYPOINT=$(cat extension.json | jq -M '.entrypoint // .commands[0].entrypoint')
if [ "null" = "$ENTRYPOINT" ]; then
    echo "WARN: $1 extension.json is missing 'entrypoint' property"
    exit 1
fi
DEPENDS_ON=$(cat extension.json | jq -M '.depends_on // .commands[0].depends_on')
if [ "null" = "$DEPENDS_ON" ]; then
    echo "WARN: $1 extension.json is missing 'depends_on' property"
    exit 1
fi

cat extension.json | jq ".version |= \"$VERSION\"" > ../../../SA/$1/extension.json
cd ../../../SA/$1/
cp ../../LICENSE .
MANIFEST=$(cat ./extension.json | base64 -w 0)
# Use package_name if available, otherwise command_name (for V1 manifests)
PACKAGE_NAME=$(cat extension.json | jq -r '.package_name // .command_name // .commands[0].command_name')
tar -czvf ../../packages/$PACKAGE_NAME.tar.gz .
cd ../../packages
if [ -f ~/minisign.key ]; then
    bash -c "echo \"\" | ~/minisign -s ~/minisign.key -S -m ./$PACKAGE_NAME.tar.gz -t \"$MANIFEST\" -x $PACKAGE_NAME.minisig"
fi
