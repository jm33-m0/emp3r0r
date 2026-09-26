# PetitPotam authentication attack #

Reflective DLL implementation of the PetitPotam attack published by [@topotam77](https://twitter.com/topotam77).

## Background of PetitPotam

The PetitPotam attack is a way to remotely coerce a Windows hosts to authenticate to other systems. It abuses functionality of the MS-EFSRPC (Encrypting File System Remote) protocol. It was incompletely patched by Microsoft in the September 2021 patch round. At this moment, it is unclear if Microsoft will provide additional patches.

MS-EFSRPC allows an attacker to make a system authenticate to a destination of the attackers choosing using NTLM authentication. When using a NTLM relaying tool like Impacket's ntlmrelayx or python responder we can relay to another system that accepts NTLM based authentication. The impact differs on the source and destination systems. But in some cases it may provide you with near-instant Domain Admin privileges.

## Advantages over public implementations

This implementation of PetitPotam has some advantages over other public exploits:

* It can be used directly from Cobalt Strike or other C2 frameworks because it comes in form of a reflective DLL.
* It detects if the target system is patched. If so, it uses an alternative EFS RPC call that remained unpatched in the September 2021 patch round.

## How to compile
1. Make sure you have a Windows machine running Visual Studio (Community) 2019 or later.
2. Enter the SOURCE folder within the tool folder.
3. Use to open the `PetitPotam.sln` file.
4. Build the solution in Release mode for the x64 platform.
5. The `PetitPotam.dll` will be copied automatically to the PetitPotam folder during build (Post-Build event).

## Usage
* Use the Cobalt Strike "Script Manager" to load the CNA script from the PetitPotam folder.
* Prepare your relaying setup.
* Perform the attack using syntax: `PetitPotam [capture server ip or hostname] [target server ip or hostname]`

## Examples (ADCS Attack)

SpecterOps published a [paper](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) in which they describe, among other things, how to gain full control over a Windows domain when abusing vulnerabilities in the "Active Directory Certificate Service" (ADCS). This research covers a vulnerability named ESC8 that allows NTLM based authentication to the AD CS Web Enrollment server.
  
Using the relayed machine account (NTLM) authentication from a Domain Controller we can enroll a machine certificate on the ADCS web enrollment server and use this certificate to request the Domain Controller its Kerberos TGT. 
With the Domain Controller TGT we can then perform a DCSync and pull the NTLM hash of any account (krbtgt e.g.).

## Credits
This code is inspired by [@topotam77](https://twitter.com/topotam77) PetitPotam exploit: https://github.com/topotam/PetitPotam
