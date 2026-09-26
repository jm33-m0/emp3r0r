# Klist BOF

A BOF tool to display a list of currently cached Kerberos tickets.

## How to compile
1. Make sure that Mingw-w64 (including mingw-w64-binutils) has been installed.
2. Enter the SOURCE folder within the tool folder.
3. Type "make" to compile the object files.
4. Use Cobal Strike script manager to import the `Klist.cna` script.

## Usage
Running the tool is straightforward. Once you imported the CNA script using Cobalt Strike's Script Manager, they are available as Cobalt Strike commands that can be executed within a beacon. This tools supports the following commands:

* Klist [optional purge]
* Klist get SPN

## Examples
* Display currently cached Kerberos tickets: `klist`
* Display and purge currently cached Kerberos tickets: `klist purge`
* Request a service ticket for SPN HOST/FLAPDROL: `klist get HOST/FLAPDROL`

## Support
This BOF tool has been successfully compiled on Mac OSX systems and used on Windows 8.1+ (x64) systems. Compiling the BOF code should also work on other systems (Linux, Windows) that have the Mingw-w64 compiler installed.
