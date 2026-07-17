#!/bin/bash

# variables
REPOROOT=$(pwd)
BOF=$1
BOFTYPE=$2
SRCDIR="$REPOROOT/src/$BOFTYPE/$BOF"
OUTDIR="$REPOROOT/$BOFTYPE/$BOF"
PKGS=$REPOROOT/packages

# compile
echo "[+] Changing directory: $SRCDIR"
cd $SRCDIR
echo "[+] Compiling: $BOF"
make

# archive
echo "[+] Creating artifact:"
mkdir artifacts # $SRCDIR/artifacts/
mv $OUTDIR/*.o ./artifacts/
VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "0.0.0-dev")

# Check extension.json for required fields (supports both V1 and V2 manifests)
# V1: fields at top level
# V2: fields inside commands[0]

HELP=$(cat extension.json | jq -M '.help // .commands[0].help')
if [ "null" = "$HELP" ]; then
    echo "WARN: $BOF extension.json is missing 'help' property"
    exit 1
fi
NAME=$(cat extension.json | jq -M .name)
if [ "null" = "$NAME" ]; then
    echo "WARN: $BOF extension.json is missing 'name' property"
    exit 1
fi
CMD_NAME=$(cat extension.json | jq -M '.command_name // .commands[0].command_name')
if [ "null" = "$CMD_NAME" ]; then
    echo "WARN: $BOF extension.json is missing 'command_name' property"
    exit 1
fi
ENTRYPOINT=$(cat extension.json | jq -M '.entrypoint // .commands[0].entrypoint')
if [ "null" = "$ENTRYPOINT" ]; then
    echo "WARN: $BOF extension.json is missing 'entrypoint' property"
    exit 1
fi
DEPENDS_ON=$(cat extension.json | jq -M '.depends_on // .commands[0].depends_on')
if [ "null" = "$DEPENDS_ON" ]; then
    echo "WARN: $BOF extension.json is missing 'depends_on' property"
    exit 1
fi

cat extension.json | jq ".version |= \"$VERSION\"" > ./artifacts/extension.json
cd artifacts # ./src/$BOFTYPE/$BOF/artifacts/
echo
pwd
ls -l
echo

# package
mkdir -p $PKGS
echo "[+] Creating package:"
MANIFEST=$(cat extension.json | base64 -w 0)
# Use package_name if available, otherwise command_name (for V1 manifests)
PACKAGE_NAME=$(cat extension.json | jq -r '.package_name // .command_name // .commands[0].command_name')
echo "[+] executing: tar -czvf $PKGS/$PACKAGE_NAME.tar.gz ."
tar -czvf $PKGS/$PACKAGE_NAME.tar.gz .
cd $PKGS
echo
pwd
ls -l

# sign
if [ -f ~/minisign.key ]; then
    echo "[+] Signing package:"
    bash -c "echo \"\" | ~/minisign -s ~/minisign.key -S -m ./$PACKAGE_NAME.tar.gz -t \"$MANIFEST\" -x $PACKAGE_NAME.minisig"
fi