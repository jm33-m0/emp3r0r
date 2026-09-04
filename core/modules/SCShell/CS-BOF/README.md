# BOF Version of SCShell for Cobalt Strike

## How to compile 

Use the provided [Makefile](./Makefile) (currently implemented
for the Linux MinGW-w64 cross-compiler):

```
make
```

## Using the BOF in Cobalt Strike

Simply load the aggressor script [scshell.cna](./scshell.cna).

Then you have the beacon command `scshell`. For getting cmd options:

```
beacon> help scshell
```

Two authentication methods are implemented (in different BOFs):

* impersonating the current process token
* using the logon session linked to the process token (useful with `make_token` or `pth`)

## Lateral movement using builtin jump

Also implemented the lateral movement technique using the internal
`jump` beacon command, for listing available methods
(`scshell` and `scshell64` should be there):

```
beacon> jump
```

For using `jump`:

```
beacon> help jump
```

There are configurable settings for the `jump scshell` and the
`jump scshell64` techniques. Here it is:

```
beacon> help scshell-settings
Use: scshell-settings [setting] [value]

Set settings to be used for the `jump scshell[64]` cmds.

Supported settings:
  service - Set the service to be changed
  exepath - Remote exe path for uploaded artifact
  delay - Add an optional delay (in seconds) between remote file copy and cmd execution (via starting the temporarily changed service)

Without any options the command simply displays the current settings.
```

Note that this implementation of jump works similarly to other
builtin jump implementations, thus it breaks the beauty of SCShell
filelessness (it pushes an artifact svcexe to the remote target).
However, there is an optional configurable delay between uploading
the artifact to the remote target and detonating it, this might be
useful for specific EDR evasions.
