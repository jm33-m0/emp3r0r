# WdToggle BOF

A BOF tool that can be used to enable **WDigest** credential caching and to circumvent **Credential Guard** (if enabled).
Additional guidance can be found in this blog post: https://outflank.nl/blog/?p=1592

## Background
This tool is based on the following excellent blog posts:

[Exploring Mimikatz - Part 1 - WDigest](https://blog.xpnsec.com/exploring-mimikatz-part-1/)

[Bypassing Credential Guard](https://teamhydra.blog/2020/08/25/bypassing-credential-guard/) 

Utilizing direct systems calls via inline assembly in BOF code provides a more opsec safe way of interacting with the LSASS process. Using direct system calls avoids AV/EDR software intercepting user-mode API calls.

Visual Studio (C++) does not support inline assembly for x64 processors. So in order to write a single Beacon Object File containing our compiled / assembled code code we must use the [Mingw-w64](http://mingw-w64.org) (GCC for Windows) compiler.

## What is this repository for?
* Demonstrate the usage of direct systems calls using inline-assembly to provide a more opsec safe way of interacting with the LSASS process.
* Enable **WDigest** credential caching by toggling the ``g_fParameter_UseLogonCredential`` global parameter to 1 within the LSASS process (wdigest.dll module).
* Circumventing **Credential Guard** (if enabled) by toggling the ``g_IsCredGuardEnabled`` variable to 0 within the LSASS process (wdigest.dll module).
* Execute this code within the Beacon process using a [Beacon object file](https://www.cobaltstrike.com/help-beacon-object-files).

## How to compile
1. Make sure that Mingw-w64 (including mingw-w64-binutils) has been installed.
2. Enter the SOURCE folder within the tool folder.
3. Type "make" to compile the object files.
4. Use Cobal Strike script manager to import the `WdToggle.cna` script.
5. Run the Cobaltstrike ``logonpasswords`` command (Mimikatz) and notice that clear text passwords are enabled again for new user logins or users who **unlock** their desktop session.

## Usage
Running the tools is straightforward. Once you imported the CNA script using Cobalt Strike's Script Manager, they are available as Cobalt Strike commands that can be executed within a beacon. This tools supports the following command:

* `WdToggle`

## Limitations
* This memory patch is not reboot persistent, so after a reboot you must rerun the code.
* The memory offset to the ``wdigest!g_fParameter_UseLogonCredential`` and ``wdigest!g_IsCredGuardEnabled`` global variable could change between Windows versions and revisions. We provided some offsets for different builds, but these can change in future releases. You can add your own version offsets which can be found using the Windows debugger tools.
* Use Winbindex (https://winbindex.m417z.com/?file=wdigest.dll) to download specific wdigest.dll versions.
* Install the ``Debugging Tools for Windows`` which are included within the ``Windows Software Development Kit`` (SDK).
* Run the commands below to retrieve the offset values from the OS included (or a specific downloaded) version of wdigest.dll.

```
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64>cdb.exe -z C:\Windows\System32\wdigest.dll

0:000>x wdigest!g_fParameter_UseLogonCredential
00000001`800361b4 wdigest!g_fParameter_UseLogonCredential = <no type information>
0:000> x wdigest!g_IsCredGuardEnabled
00000001`80035c08 wdigest!g_IsCredGuardEnabled = <no type information>
0:000>
```

## Detection
To detect credential theft through LSASS memory access, we could use a tool like [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
Sysmon can be configured to log processes opening a handle to the lsass.exe process. With this configuration applied, we can gather telemetry for suspicious processes accessing the LSASS process and help detecting possible credential dumping activity. Of course, there are more options to detect credential theft, for example using an advanced detection platform like Windows Defender ATP. But if you don’t have the budget and luxury of using these platforms, then Sysmon is that free tool that can help to fill up the gap.

## Support
This BOF tool has been successfully compiled on Mac OSX systems and used on Windows 8.1+ (x64) systems. Compiling the BOF code should also work on other systems (Linux, Windows) that have the Mingw-w64 compiler installed.

## Credits
* Adam Chester [@\_xpn\_](https://twitter.com/_xpn_)
* N4kedTurtle from [Team Hydra](https://teamhydra.blog)
