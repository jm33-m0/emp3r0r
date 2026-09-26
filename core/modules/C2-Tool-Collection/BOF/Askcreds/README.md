# Askcreds BOF

A BOF tool that can be used to collect passwords using CredUIPromptForWindowsCredentialsName.

## How to compile
1. Make sure that Mingw-w64 (including mingw-w64-binutils) has been installed.
2. Enter the SOURCE folder within the tool folder.
3. Type "make" to compile the object files.
4. Use Cobal Strike script manager to import the `Askcreds.cna` script.

## Usage
Running the tools is straightforward. Once you imported the CNA script using Cobalt Strike's Script Manager, they are available as Cobalt Strike commands that can be executed within a beacon. This tools supports the following commands:

* `Askcreds [optional reason]`
  
## Examples
* Just ask with default reason: `Askcreds`
* Ask with a specific reason: `Askcreds Gimme Your Password!`

## Limitations
This BOF is threaded and waits 60 seconds for the thread to return. If the target users ignores the cred popup the beacon will be unresponsive for max 60 sec.

## Support
This BOF tool has been successfully compiled on Mac OSX systems and used on Windows 8.1+ (x64) systems. Compiling the BOF code should also work on other systems (Linux, Windows) that have the Mingw-w64 compiler installed.
