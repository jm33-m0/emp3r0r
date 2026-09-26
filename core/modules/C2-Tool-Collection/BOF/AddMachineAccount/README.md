# AddMachineAccount BOF

A BOF tool that can be used to abuse default Active Directory machine quota (ms-DS-MachineAccountQuota) settings to add rogue machine accounts. These accounts can then be used to stage other attacks.

This BOF repo currently consists of the following individual tools:

* **GetMachineAccountQuota**: read the MachineAccountQuota value from the Active Directory domain.
* **AddMachineAccount**: add a computer account to the Active Directory domain with a specified or random generated password.
* **DelMachineAccount**: remove a computer account from the Active Directory domain (elevated domain privileges needed).

## How to compile
1. Make sure that Mingw-w64 (including mingw-w64-binutils) has been installed.
2. Enter the SOURCE folder within the tool folder.
3. Type "make" to compile the object files.
4. Use Cobal Strike script manager to import the `MachineAccounts.cna` script.

## Usage
Running the tools is straightforward. Once you imported the CNA script using Cobalt Strike's Script Manager, they are available as Cobalt Strike commands that can be executed within a beacon. This tools supports the following commands:

* `GetMachineAccountQuota`
* `AddMachineAccount [*Computername] [Optional Password]`
* `DelMachineAccount [*Computername]`

*\* Computername does not have to end with an **$** ​​character.*

## Support
This BOF tool has been successfully compiled on Mac OSX systems and used on Windows 8.1+ (x64) systems. Compiling the BOF code should also work on other systems (Linux, Windows) that have the Mingw-w64 compiler installed.
