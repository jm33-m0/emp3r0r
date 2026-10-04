#!/bin/sh
# Build a pinned OpenSSH server for the ssh_harvest real-sshd e2e test.
#
# Downloads the portable release into <prefix>, verifies its SHA-256, and
# builds + installs sshd, sshd-session and sshd-auth (the binary that runs
# auth_password) under <prefix>/install. The result is cached: a second run
# with the same prefix is a no-op.
#
# Usage: build_openssh.sh <prefix>
set -eu

VERSION="${OPENSSH_VERSION:-10.5p1}"
SHA256="${OPENSSH_SHA256:-d44d28a839ea9daf969cc69150fde59910b2b39361dad81a3bd6cbd19218db11}"
PREFIX="${1:?usage: build_openssh.sh <prefix>}"

tarball="$PREFIX/openssh-$VERSION.tar.gz"
srcdir="$PREFIX/openssh-$VERSION"
install="$PREFIX/install"

if [ -x "$install/sbin/sshd" ] && [ -x "$install/libexec/sshd-auth" ] &&
    [ -x "$install/libexec/sshd-session" ]; then
	echo "$install"
	exit 0
fi

command -v curl >/dev/null 2>&1 || { echo "build_openssh: curl not found" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "build_openssh: sha256sum not found" >&2; exit 1; }
command -v cc >/dev/null 2>&1 || { echo "build_openssh: C compiler not found" >&2; exit 1; }

mkdir -p "$PREFIX"
if [ ! -f "$tarball" ]; then
	curl -fsSL -o "$tarball" \
		"https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-$VERSION.tar.gz"
fi
echo "$SHA256  $tarball" | sha256sum -c - >/dev/null

if [ ! -d "$srcdir" ]; then
	tar xzf "$tarball" -C "$PREFIX"
fi

cd "$srcdir"
if [ ! -f Makefile ]; then
	# --without-pam keeps the dependency set small (libcrypto + zlib +
	# libcrypt). -O2 -g plus --disable-strip keeps .symtab so the test can
	# locate auth_password and derive its probe pattern.
	./configure --prefix="$install" --without-pam --with-ssl-dir=/usr \
		--with-privsep-path="$PREFIX/privsep" --disable-strip \
		CFLAGS="-O2 -g" >/dev/null
fi

jobs="$(nproc 2>/dev/null || echo 2)"
make -j"$jobs" sshd sshd-session sshd-auth ssh-keygen >/dev/null
make install >/dev/null

mkdir -p "$PREFIX/privsep"
chmod 0755 "$PREFIX/privsep"
echo "$install"
