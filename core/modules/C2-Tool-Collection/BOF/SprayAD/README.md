# SprayAD BOF

A BOF tool to perform a fast Kerberos or LDAP password spraying attack against Active Directory.
This tool can help Red and Blue teams to audit Active Directory useraccounts for weak, well known or easy guessable passwords and can help Blue teams to assess whether these events are properly logged and acted upon.
When this tool is executed, it generates event IDs 4771 (Kerberos pre-authentication failed) instead or event ID 4625 (logon failure) when using LDAP for spraying. Event ID 4771 is not audited by default on domain controllers and therefore this tool might help evading detection while password spraying.

## How to compile
1. Make sure that Mingw-w64 (including mingw-w64-binutils) has been installed.
2. Enter the SOURCE folder within the tool folder.
3. Type "make" to compile the object files.
4. Use Cobal Strike script manager to import the `SprayAD.cna` script.

## Usage
Running the tool is straightforward. Once you imported the CNA script using Cobalt Strike's Script Manager, they are available as Cobalt Strike commands that can be executed within a beacon. This tools supports the following commands:

* SprayAD [password to test] [filter <optional> <example: admin*>] [ldap <optional>]

## Examples
* Kerberos password spray: `SprayAD Welcome123`
* Kerberos password spray with account filter to target accounts beginning with adm: `SprayAD Welcome123 adm*`
* LDAP password spray: `SprayAD Welcome123 ldap`

## Limitations
Running a Kerberos spray within a large Active Directory environment could take a while, so the beacon will not respond during the scan. To scan more efficiently, it is advisable to use filters to test interesting accounts first, such as admin or service accounts. In addition, scanning through ldap is much faster, however, this generates event id 4625 which might trigger an detection alarm.

## Note to Red
Make sure you always check the Active Directory password and lockout policies before spraying to avoid lockouts.

## Note to Blue
To detect Active Directory Password Spraying, make sure to setup centralized logging and alarming within your IT environment and enable (at least) the following Advanced Audit policy on your Domain Controllers: 

```
Audit Kerberos Authentication Service (Success & Failure). 
This policy will generate Windows Security Log Event ID 4771 (Kerberos pre-authentication failed).
```

More info can be found in the following post by Sean Metcalf:
https://www.trimarcsecurity.com/post/2018/05/06/trimarc-research-detecting-password-spraying-with-security-event-auditing

## Support
This BOF tool has been successfully compiled on Mac OSX systems and used on Windows 8.1+ (x64) systems. Compiling the BOF code should also work on other systems (Linux, Windows) that have the Mingw-w64 compiler installed.