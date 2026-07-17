# Remote Operations BOF

This repo serves as an addition to our previously released [SA](https://github.com/trustedsec/CS-Situational-Awareness-BOF) repo. Our original stance was that we would not release our tooling that modified other systems, and we would only provide information gathering tooling in a ready to go format.

Over time, we have seen many other public security companies release their offensive facing tooling, and we now feel it is appropriate for us to release a portion of our offensive tooling.

Nothing in this repo is particularly special, it is basic Microsoft Windows operations in BOF form. These primitives can be used for a large variety of operations.

## Injection BOF

We have decided to include the injection BOFs that we use when doing EDR detection testing. These BOFs are provided as is and will not be supported (everything under src/Injection and Injection/*)

You are welcome to use these, but issues opened related to these will be closed without review.

## Available Remote Operations commands

|Command|Usage|Notes|
|-------|-----|-----|
|adcs_request| adcs_request [CA] [OPT:TEMPLATE] [OPT:SUBJECT] [OPT:ALTNAME] [OPT:INSTALL] [OPT:MACHINE] [OPT:ADD_APP_POLICY] [OPT:DNS] | Request an enrollment certificate|
|adcs_request_on_behalf| adcs_request_on_behalf [TEMPLATE] [REQUESTER] [ENROLLMENT_AGENT.pfx] [Download_Name] | Request an enrollment certificate on behalf of another user|
|adduser| adduser [USERNAME] [PASSWORD] [SERVER] | Add specified user to a machine|
|addusertogroup| addusertogroup [USERNAME] [GROUPNAME] [SERVER] [DOMAIN] | Add specified user to a group|
|ask_mfa | ask_mfa [NUMBER] | Displays a fake Microsoft Authenticator approval dialog with the specified number. |
|chromeKey| chromeKey | Decrypt the provided base64 encoded Chrome key|
|disableuser| disableuser [USERNAME] [DOMAIN] | Disable the specified user account|
|enableuser| enableuser [USERNAME] [DOMAIN] | Enable and unlock the specified user account|
|get_azure_token| get_azure_token [CLIENT ID] [SCOPE] [BROWSER] [OPT:HINT] [OPT:BROWSER PATH] | Attempts to complete an OAuth codeflow grant against azure using saved logins |
|get_priv| get_priv [Privledge Name] | Activate the specified token privledge, more for non-cobalt strike users|
|ghost_task| ghost_task [HOSTNAME/LOCALHOST] [OPERATION] [TASKANME] [PROGRAM] [ARGUMENT] [USERNAME] [SCHEDULETYPE] [TIME/SECOND] [DAY] | Add/Delete a ghost task. |
|global_unprotect| global_unprotect | Locates and Decrypts GlobalProtect config files converted from: [GlobalUnProtect](https://github.com/rotarydrone/GlobalUnProtect/tree/409d64b097e0a928a5545051e40e1566e9c26bd0)|
|lastpass | lastpass [NUMBER OF PIDs] [PID],[PID],[PID],[PID] ... | Search Chrome, brave memory for LastPass passwords and data|
|make_token_cert| make_token_cert [.PFX LOCAL PATH] [OPT:PFX PASSWORD]| Impersonates a user using the altname of a .pfx file |
|office_tokens| office_tokens [PID] | Collect Office JWT Tokens from any Office process|
|procdump| procdump [PID] [FILEOUT] | Dump the specified process to the specified output file|
|ProcessDestroy| ProcessDestroy [PID] [OPT:HANDLEID] | Close handle(s) in a process|
|ProcessListHandles| ProcessListHandles [PID] | List all open handles in a specified process|
|reg_delete| reg_delete [OPT:HOSTNAME] [HIVE] [REGPATH] [OPT:REGVALUE] | Delete a registry key|
|reg_save| reg_save [HIVE] [REGPATH] [FILEOUT] | Save a registry hive to disk|
|reg_set| reg_set [OPT:HOSTNAME] [HIVE] [KEY] [VALUE] [TYPE] [DATA] | Set / create a registry key|
|sc_config| sc_config [SVCNAME] [BINPATH] [ERRORMODE] [STARTMODE] [OPT:HOSTNAME] | Configure an existing service|
|sc_create| sc_create [SVCNAME] [DISPLAYNAME] [BINPATH] [DESCRIPTION] [ERRORMODE] [STARTMODE] [OPT:TYPE] [OPT:HOSTNAME] | Create a new service|
|sc_delete| sc_delete [SVCNAME] [OPT:HOSTNAME] | Delete an existing service|
|sc_description| sc_description [SVCNAME] [DESCRIPTION] [OPT:HOSTNAME] | Modify an existing services description|
|sc_failure| sc_failure [SVCNAME] [RESETPERIOD] [REBOOTMESSAGE] [COMMAND] [NUMACTIONS] [ACTIONS] [OPT:HOSTNAME] | Configures the actions upon failure of an existing service|
|sc_start| sc_start [SVCNAME] [OPT:HOSTNAME] | Start an existing service|
|sc_stop| sc_stop [SVCNAME] [OPT:HOSTNAME] | Stop an existing service|
|schtaskscreate| schtaskscreate [OPT:HOSTNAME] [USERNAME] [PASSWORD] [TASKPATH] [USERMODE] [FORCEMODE] | Create a new scheduled task (via xml definition)|
|schtasksdelete| schtasksdelete [OPT:HOSTNAME] [TASKNAME] [TYPE] | Delete an existing scheduled task|
|schtasksrun| schtasksrun [OPT:HOSTNAME] [TASKNAME] | Start a scheduled task|
|schtasksstop| schtasksstop [OPT:HOSTNAME] [TASKNAME] | Stop a running scheduled task|
|setuserpass| setuserpass [USERNAME] [PASSWORD] [DOMAIN] | Set a user's password|
|shspawnas| shspawnas [DOMAIN] [USERNAME] [PASSWORD] [OPT:SHELLCODEFILE] | A misguided attempt at injecting code into a newly spawned process|
|shutdown| shutdown [HOSTNAME] \"[MESSAGE]\" [TIME] [CLOSEAPPS] [REBOOT] | Shutdown or reboot a local or remote computer, with or without a warning/message
|slackKey | slackKey | Attempts to harvest slack keys from "%APPDATA%\Slack\Local State" |
|slack_cookie| slack_cookie [PID] | Collect the Slack authentication cookie from a Slack process|
|suspendresume | suspendresume [0\|1] [PID] | Suspend a process with 1, resume a process with 0|
|unexpireuser| unexpireuser [USERNAME] [DOMAIN] | Set a user account to never expire|


## Contributing

This repo is intended for single task Windows primitives. That is to say, even if it takes multiple calls, creating a scheduled task is appropriate.

A command that would attempt to pre-generate an implant and perform automated movement using the BOFs in this repo would be awesome. But is not appropriate for submission to this repo directly.

### Code expectations
* Your code should compile without errors when using the default makefile
* Any new BOF defines for resolving functions will be placed in src/common/bofdefs.h
* Code will compile together using the default Makefile (single entry.c file)
* Code will likewise be compatible with the existing toolchain (mingw)
* Code will be written in C. This is to standardize and my personal confidence in validating the code.

### What to expect as a contributor
After a pull request is received, it will receive an in-depth code review and testing.  </br>
After testing is completed, we will have zero or more rounds of change requests based on findings until there are no issues in the code. At that point it will be accepted into the repository, and your GitHub username will be added to our credit list. If you would prefer not to be added or some other handle to be used, just let me know.

## Want to Learn More?
If you've found these beacon object files helpful and want to write some of your own bofs following a similar style we invite you to check out our [Beacon Object File (BOF) Development](https://learn.trustedsec.com/courses/cd84409a-36af-4507-be2c-ca7ad1e9fd2d) course.  
The course gives a breif overview of the history of beacon object files and then dives into a variety of challenge problems that aim to teach you how to leverage a variety of windows technologies when developing your own beacon object files.
