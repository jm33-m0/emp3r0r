# COFF Loader

This is a quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it. The only exception is that the injection related beacon compatibility functions are just empty.

The main goal is to provide a working example and maybe be useful to someone.


## Parts
There are a few parts to it they are listed below.

- beacon_compatibility: This is the beacon internal functions so that you can load BOF files and run them.
- COFFLoader: This is the actual coff loader, and when built for nix just loads the 64 bit object file and parses it.
- test: This is the example "COFF" file, will build to the COFF file for you when make is called.
- beacon_generate: This is a helper script to build strings/arguments compatible with the beacon_compatibility functions.


## Beacon Generate
This is used to generate arguments for the COFFLoader code, if the BOF takes arguments simply add the arguments with the type expected with this and generate the hex string for use.

Example usage here:
```
COFFLoader % python3 beacon_generate.py
Beacon Argument Generator
Beacon>help

Documented commands (type help <topic>):
========================================
addString  addWString  addint  addshort  exit  generate  help  reset

Beacon>addWString test
Beacon>addint 4
Beacon>generate
b'120000000a0000007400650073007400000004000000'
Beacon>reset
Beacon>addint 5
Beacon>generate
b'0400000005000000'
Beacon>exit
```

## BOF Arguments
You can find what arguments are required by each BOF by viewing the source code. Using the Net User BOF as an example, you would view the `src/SA/netuser/entry.c` file found in the `CS-Situational-Awareness-BOF` Github and then view the arguments found in the `void go()` function.

``` CPP
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    datap parser;
    wchar_t *username = NULL;
    wchar_t *domain = NULL;

    BeaconDataParse(&parser, Buffer, Length);
    username = (wchar_t *)BeaconDataExtract(&parser, NULL);
    domain = (wchar_t *)BeaconDataExtract(&parser, NULL);
    domain = *domain == 0 ? NULL : domain;
    netuserinfo(username, domain);

    printoutput(TRUE);
};
```

We can see that our Net User BOF requires a "username" and "domain" (*which we can get by running the whoami BOF*). Using the `beacon_generate.py` helper script, we would generate the arguments like this:

```
COFFLoader % python3 beacon_generate.py
Beacon Argument Generator
Beacon>addWString Administrator
Beacon>addWString client2
Beacon>generate
b'340000001c000000410064006d0069006e006900730074007200610074006f00720000001000000063006c00690065006e00740032000000'
Beacon>exit
```

Lastly, copy the hexified numeric values (just the numbers) into your execution command
``` Shell
COFFLoader64.exe go ..\CS-Situational-Awareness-BOF\SA\netuser\netuser.x64.o 340000001c000000410064006d0069006e006900730074007200610074006f00720000001000000063006c00690065006e00740032000000
```
You can find more detailed examples at this link:\
https://trustedsec.com/blog/situational-awareness-bofs-for-script-kiddies



## Running
An example of how to run a BOF is below.

```
COFFLoader64.exe go test64.out
COFFLoader64.exe go ..\CS-Situational-Awareness-BOF\SA\whoami\whoami.x64.o
```
