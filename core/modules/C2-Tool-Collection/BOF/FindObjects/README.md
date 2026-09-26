# FindObjects BOF

A BOF tool that can be used to enumerate processes for specific loaded modules or process handles.

### What is this repository for? ###

* Enumerate processes for specific loaded modules (e.g. winhttp.dll, amsi.dll or clr.dll).
* Enumerate processes for specific process handles (e.g. lsass.exe).
* Avoid using the Windows and Native APIs as much as possible (to avoid userland hooks).
* Execute this code within the beacon process using [Beacon object files](https://www.cobaltstrike.com/help-beacon-object-files) to avoid fork&run.

## How to compile
1. Make sure that Mingw-w64 (including mingw-w64-binutils) has been installed.
2. Enter the SOURCE folder within the tool folder.
3. Type "make" to compile the object files.
4. Use Cobal Strike script manager to import the `FindObjects.cna` script.

## Usage
Running the tools is straightforward. Once you imported the CNA script using Cobalt Strike's Script Manager, they are available as Cobalt Strike commands that can be executed within a beacon. This tools supports the following commands:

* The ``FindModule example.dll`` command can be used to identify processes which have a certain module loaded, for example the .NET runtime ``clr.dll`` or the ``winhttp.dll`` module. This information can be used to select a more opsec safe spawnto candidate when using Cobalt Strike's ``execute-assembly`` or before injecting an exfill beacon shellcode using the ``shinject`` command.

* The ``FindProcHandle example.exe`` command can be used to identify processes with a specific process handle in use, for example processes using a handle to the  ``lsass.exe`` process. If there's a process within the system with a ``lsass.exe`` process handle, we could use this existing process/handle to read or write memory without opening a new process handle. This bypasses certain AV/EDR's capabilities of detecting and blocking LSASS process/memory access.

## Support
This BOF tool has been successfully compiled on Mac OSX systems and used on Windows 8.1+ (x64) systems. Compiling the BOF code should also work on other systems (Linux, Windows) that have the Mingw-w64 compiler installed.
