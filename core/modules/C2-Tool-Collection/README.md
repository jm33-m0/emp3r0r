# Outflank - C2 Tool Collection

> ## emp3r0r integration
>
> This tree is the [Outflank C2 Tool Collection](https://github.com/outflanknl/C2-Tool-Collection)
> adopted as an emp3r0r module suite. `config.json` registers every BOF as a
> top-level console command; the per-parameter help text (shown by
> `<command> --help`) is the command documentation. Run `./make_all.sh` to
> build the `.o` objects, or let `core/build.py` do it during a release build.
>
> Deviations from upstream needed by the emp3r0r build/loader:
>
> - The per-tool `Makefile`s drop `-fno-leading-underscore`: it is rejected by
>   the zig/clang cross compiler, and the COFFLoader already prepends the
>   underscore to the 32-bit `go` entry symbol itself.
> - `AddMachineAccount.c` and `CVE-2022-26923.c` treat an empty password as
>   absent. emp3r0r always packs declared BOF arguments, so an omitted password
>   arrives as `""` rather than `NULL`; this preserves the original
>   "generate a random password" behaviour.
>
> Compiled objects are build artifacts and are not checked in.

This repository contains a collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques.

These tools are not part of our [commercial OST product](https://outflank.nl/services/outflank-security-tooling/) and are written with the goal of contributing to the community to which we owe a lot. Currently this repo contains a section with [BOF](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm) (Beacon Object Files) tools and a section with other tools (exploits, reflective DLLs, etc.).
All these tools are written by our team members and are used by us in red team assignments. Over time, more tools will be added or modified with new techniques or functionality.

## Toolset contents
The toolset currently consists of the following tools:

***Beacon Object Files (BOF)***

|Name|Decription|
|----|----------|
|**[AddMachineAccount](BOF/AddMachineAccount)**|Abuse default Active Directory machine quota settings (ms-DS-MachineAccountQuota) to add rogue machine accounts.|
|**[Askcreds](BOF/Askcreds)**|Collect passwords by simply asking.|
|**[CVE-2022-26923](BOF/CVE-2022-26923)**|CVE-2022-26923 Active Directory (ADCS) Domain Privilege Escalation exploit.|
|**[Domaininfo](BOF/Domaininfo)**|Enumerate domain information using Active Directory Domain Services.|
|**[FindObjects](BOF/FindObjects)**|Enumerate processes for specific loaded modules or process handles.|
|**[Kerberoast](BOF/Kerberoast)**|List all SPN enabled user/service accounts or request service tickets (TGS-REP) which can be cracked offline using HashCat.|
|**[KerbHash](BOF/KerbHash)**|Hash password to kerberos keys (rc4_hmac, aes128_cts_hmac_sha1, aes256_cts_hmac_sha1, and des_cbc_md5).|
|**[Klist](BOF/Klist)**|Displays a list of currently cached Kerberos tickets.|
|**[Lapsdump](BOF/Lapsdump)**|Dump LAPS passwords from specified computers within Active Directory.|
|**[PetitPotam](BOF/PetitPotam)**|BOF implementation of the PetitPotam attack published by [@topotam77](https://twitter.com/topotam77).|
|**[Psc](BOF/Psc)**|Show detailed information from processes with established TCP and RDP connections.|
|**[Psw](BOF/Psw)**|Show window titles from processes with active windows.|
|**[Psx](BOF/Psx)**|Show detailed information from all processes running on the system and provides a summary of installed security products and tools.|
|**[Psm](BOF/Psm)**|Show detailed information from a specific process id (loaded modules, tcp connections e.g.).|
|**[Psk](BOF/Psk)**|Show detailed information from the windows kernel and loaded driver modules and provides a summary of installed security products (AV/EDR drivers).|
|**[ReconAD](BOF/ReconAD)**|Use ADSI to query Active Directory objects and attributes.|
|**[Smbinfo](BOF/Smbinfo)**|Gather remote system version info using the NetWkstaGetInfo API without having to run the Cobalt Strike port (tcp-445) scanner.|
|**[SprayAD](BOF/SprayAD)**|Perform a fast Kerberos or LDAP password spraying attack against Active Directory.|
|**[StartWebClient](BOF/StartWebClient)**|Start the WebClient Service programmatically from user context using a service trigger.|
|**[WdToggle](BOF/WdToggle)**|Patch lsass to enable WDigest credential caching and to circumvent Credential Guard (if enabled).|
|**[Winver](BOF/Winver)**|Display the version of Windows that is running, the build number and patch release (Update Build Revision).|

***Others***

|Name|Decription|
|----|----------|
|**[PetitPotam](Other/PetitPotam)**|Reflective DLL implementation of the PetitPotam attack published by [@topotam77](https://twitter.com/topotam77)|
|**[RemotePipeList](Other/RemotePipeList)**|.NET tool to enumerate remote named pipes|

## How to use
1. Clone this repository.
2. Each tool contains an individual README.md file with instructions on how to compile and use the tool. With this approach, we want to give the user the choice of which tool they want to use without having to compile all the other tools.
3. If you would like to compile all the BOF tools at once, type `make` within the [BOF](BOF/) subfolder.
