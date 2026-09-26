# RemotePipeList

A small tool that can list the named pipes bound on a remote system.

## Usage

Usage: `remotepipelist <target> <(domain\)username> <password>`

- CobaltStrike
    - Load the CNA using the script manager and ensure the exe is in the same folder.
- Stage1
    - Place the python file in the `shared/tasks` folder. Restart your Stage1 server.

## Background

Local pipe listing is possible using built-in Windows APIs, SysInternal's PipeList, and through BOF - see [xPipe](https://github.com/boku7/xPipe).

However, remote pipe listing is a bit more challenging. While impacket bundles `smbclient.py` which can handle listing remote named pipes, no tool existed (that I know of) that could be executed through an implant.

For more information, see [https://outflank.nl/blog/2023/10/19/listing-remote-named-pipes/](https://outflank.nl/blog/2023/10/19/listing-remote-named-pipes/).

## License

This tool makes use of:

- SMBLibrary (LGPL): [https://github.com/TalAloni/SMBLibrary](https://github.com/TalAloni/SMBLibrary)

