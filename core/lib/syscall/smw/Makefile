# Regenerate desyncspoofer.syso from csrc/DesyncSpoofer.asm.
# Requires nasm; the committed .syso is what the Go linker consumes, so
# end-user builds do not need nasm installed.
desyncspoofer.syso: csrc/DesyncSpoofer.asm
	nasm -f win64 csrc/DesyncSpoofer.asm -o desyncspoofer.syso

clean:
	rm -f desyncspoofer.syso
