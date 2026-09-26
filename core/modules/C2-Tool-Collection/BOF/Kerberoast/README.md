# Kerberoast BOF

A BOF tool to list all SPN enabled user/service accounts or request service tickets (TGS-REP) which can be cracked offline using HashCat.

## How to compile
1. Make sure that Mingw-w64 (including mingw-w64-binutils) has been installed.
2. Enter the SOURCE folder within the tool folder.
3. Type "make" to compile the object files.
4. Use Cobal Strike script manager to import the `Kerberoast.cna` script.
5. To use the TicketToHashcat.py script make sure that the python dependencies are installed using: `pip install -r requirements.txt`

## Usage
Running the tool is straightforward. Once you imported the CNA script using Cobalt Strike's Script Manager, they are available as Cobalt Strike commands that can be executed within a beacon. This tools supports the following commands:

* Kerberoast [list, list-no-aes, roast or roast-no-aes] [account <optional sAMAccountName filter (default all)>]
* The tool outputs the captured tickets between TICKET tags. To convert the ticket(s) to a Hashcat compatible hash type, make sure you copy the ticket(s) (including the  <TICKET\> </TICKET\> tags) to a file and use the `TicketToHashcat.py` file to convert the output.
The TicketToHashcat.py script saves the tickets to a `roastme-<#hash-type>.txt` file.
* To crack the hashes within the file(s) use: `hashcat -m 13100` for RC4 hashes, `hashcat -m 19600` for aes128 hashes or `hashcat -m 19700` for aes256 hashes.

## Examples
* List SPN enabled accounts: `Kerberoast list`
* List SPN enabled accounts without AES encryption: `Kerberoast list-no-aes`
* Roast all SPN enabled accounts: `Kerberoast roast`
* Roast all SPN enabled accounts without AES encryption: `Kerberoast roast-no-aes`
* Roast specific accounts: `Kerberoast roast svc-test`

## Opsec
Listing and roasting tickets without specifying a sAMAccountName filter is opsec unsafe. The `servicePrincipalName=*` search filter might trigger a `LDAP Reconnaissance Activity` alert (for example when using M365 Defender).

## Support
This BOF tool has been successfully compiled on Mac OSX systems and used on Windows 8.1+ (x64) systems. Compiling the BOF code should also work on other systems (Linux, Windows) that have the Mingw-w64 compiler installed.

## Credits
This code is inspired by @cube0x0's BofRoast: https://github.com/cube0x0/BofRoast