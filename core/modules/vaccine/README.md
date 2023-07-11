# Description

This is not an emp3r0r module, you can use it to provide python3 environment and some utilities on your target host. To automate the process you can `use vaccine`.

# How to pack

In an Alpine container, install the tools you want, and

```bash
#!/bin/bash

pack_bin() {
	libs="$(ldd "$1" | grep '=>' | awk '{print $3}')"
	[[ -d lib ]] || mkdir lib
	cp -v "$1" .
	patchelf --add-rpath ./lib "$(basename "$1")"
	patchelf --set-interpreter './lib/ld-musl-x86_64.so.1' "$(basename "$1")"
	for lib in $libs; do
		echo "Adding $lib"
		name=$(basename "$lib")
		if [ -L "$lib" ]; then
			cp -v "$(readlink -f "$lib")" "./lib/$name"
		else
			cp -v "$lib" "./lib/$name"
		fi
	done
}

pack_python() {
	python_bin="$(which python3)"
	python_bin_real="$(readlink -f "$python_bin")"
	python_ver=$(basename "$python_bin_real")
	echo "Packing $python_ver"

	pack_bin "$python_bin_real" || {
		echo "Failed to pack python3"
		exit 1
	}

	mv "$python_ver" python3
	cp -r "/usr/lib/$python_ver/" .

	# libexpat.so.1
	libexpat="$(readlink -f /usr/lib/libexpat.so.1)"
	cp -v "$libexpat" lib/libexpat.so.1

	# remove python cache
	(
		cd "$python_ver" && {
			find . -name __pycache__ -type d -exec rm -rf {} \; 2>/dev/null
			find . -name "*.pyc" -type f -exec rm -rf {} \;
		}
	)

}

[[ -e build ]] && rm -rf build
mkdir build && cd build &&
	(
		echo "fzf
gdbserver
nano
nmap
patchelf
socat
rg" >bins.txt

		# pack bins
		while read -r bin; do
			pack_bin "$(which "$bin")"
		done <bins.txt &&
			rm bins.txt &&
			pack_python

		# pack python and libs
		tar -cJvpf "python3.tar.xz" "$python_ver" &&
			rm -rf "$python_ver"
		tar -cJvpf libs.tar.xz lib &&
			rm -rf lib

		# pack vaccine
		tar -cJvpf ../vaccine.tar.xz .
	)
```
