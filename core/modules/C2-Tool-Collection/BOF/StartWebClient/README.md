# StartWebClient BOF

A BOF tool to start the WebClient Service programmatically from user context using a service trigger.

## How to compile
1. Make sure that Mingw-w64 (including mingw-w64-binutils) has been installed.
2. Enter the SOURCE folder within the tool folder.
3. Type "make" to compile the object files.
4. Use Cobal Strike script manager to import the `StartWebClient.cna` script.

## Usage
Running the tools is straightforward. Once you imported the CNA script using Cobalt Strike's Script Manager, they are available as Cobalt Strike commands that can be executed within a beacon. This tools supports the following commands:

* `StartWebClient`

## Support
This BOF tool has been successfully compiled on Mac OSX systems and used on Windows 8.1+ (x64) systems. Compiling the BOF code should also work on other systems (Linux, Windows) that have the Mingw-w64 compiler installed.

## Credits
This code is inspired by the following blogpost from @tiraniddo: https://www.tiraniddo.dev/2015/03/starting-webclient-service.html
