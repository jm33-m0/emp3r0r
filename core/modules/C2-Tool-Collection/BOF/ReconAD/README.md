# ReconAD BOF

A BOF tool that can be used to query Active Directory objects and attributes.
This tool includes the following features:

* Query Active Directory using ADSI API's.
* Custom server or serverless Binding (default).
* Kerberos encrypted network communication.
* Search within the Global Catalogue.

## This BOF repo currently supports the following commands:

* **ReconAD**: use ADSI to query Active Directory objects and attributes using a custom LDAP filter.
* **ReconAD-Users**: use ADSI to query Active Directory user objects and attributes.
* **ReconAD-Computers**: use ADSI to query Active Directory computer objects and attributes.
* **ReconAD-Groups**: use ADSI to query Active Directory group objects and attributes.

## How to compile
1. Make sure that Mingw-w64 (including mingw-w64-binutils) has been installed.
2. Enter the SOURCE folder within the tool folder.
3. Type "make" to compile the object files.
4. Use Cobal Strike script manager to import the `ReconAD.cna` script.

## Usage
Running the tools is straightforward. Once you imported the CNA script using Cobalt Strike's Script Manager, they are available as Cobalt Strike commands that can be executed within a beacon. This tools supports the following commands:

* `ReconAD (custom ldap filter) [opt: comma separated ldap attributes (or -all)] [opt: max results (or -max)] [opt: -usegc (or -ldap)] [opt: server:port]`
* `Example: ReconAD (&(objectClass=user)(objectCategory=person)(sAMAccountName=*admin*)) displayName,sAMAccountName 10`

* `ReconAD-Users username [opt: comma separated ldap attributes (or -all)] [opt: max results (or -max)] [opt: -usegc (or -ldap)] [opt: server:port]`
* `Example: ReconAD-Users *admin* displayName,sAMAccountName 10 -usegc`

* `ReconAD-Computers computername [opt: comma separated ldap attributes (or -all)] [opt: max results (or -max)] [opt: -usegc (or -ldap)] [opt: server:port]`
* `Example: ReconAD-Computers *srv* name,operatingSystemVersion 20 -ldap 192.168.1.10`

* `ReconAD-Groups groupname [opt: comma separated ldap attributes (or -all)] [opt: max results (or -max)] [opt: -usegc (or -ldap)] [opt: server:port]`
* `Example: ReconAD-Groups "Domain Admins" -all -max -usegc 192.168.1.10`

## Support
This BOF tool has been successfully compiled on Mac OSX systems and used on Windows 8.1+ (x86/x64) systems. Compiling the BOF code should also work on other systems (Linux, Windows) that have the Mingw-w64 compiler installed.
