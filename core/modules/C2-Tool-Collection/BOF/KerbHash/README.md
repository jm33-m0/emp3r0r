# KerbHash BOF

A BOF port of the Mimikatz/Rubeus `hash` command to hash passwords to kerberos keys (rc4_hmac, aes128_cts_hmac_sha1, aes256_cts_hmac_sha1, and des_cbc_md5).

## How to compile
1. Make sure that Mingw-w64 (including mingw-w64-binutils) has been installed.
2. Enter the SOURCE folder within the tool folder.
3. Type "make" to compile the object files.
4. Use Cobal Strike script manager to import the `KerbHash.cna` script.

## Usage
Running the tool is straightforward. Once you imported the CNA script using Cobalt Strike's Script Manager, they are available as Cobalt Strike commands that can be executed within a beacon. This tools supports the following commands:

* KerbHash [password] [username] [domain.fqdn]

## Examples
* Hash useraccount password: `KerbHash Welcome123 adminuser domain.local`
* Hash computeraccount password: `KerbHash Welcome123 SERVER$ domain.local`

## Support
This BOF tool has been successfully compiled on Mac OSX systems and used on Windows 8.1+ (x64) systems. Compiling the BOF code should also work on other systems (Linux, Windows) that have the Mingw-w64 compiler installed.

## Credits
This code is inspired by @gentilkiwi's https://github.com/gentilkiwi/mimikatz and GhostPack/Rubeus: https://github.com/GhostPack/Rubeus