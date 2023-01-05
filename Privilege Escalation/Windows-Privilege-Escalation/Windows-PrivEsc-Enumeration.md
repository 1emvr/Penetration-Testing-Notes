# Windows PrivEsc Enumeration

- Useful tools for enumeration
```
	PrivEsc Vector Checking:

	- Seatbelt
	- winPEAS
	- PowerUp
	- SharpUp
	- JAWS
	- Watson

	Remote Session/ Application information extraction:
	
	- LaZagne
	- SessionGopher
```

It's usually a safe-bet to upload tools to `C:\Windows\Temp`. 
`BUILTIN\Users` have acces by default.

## Network Information
```bash
arp -a # ARP/MAC Tables
ipconfig /all # List IP/Network information
route print # Routing information
```

## Enumerating Protections (EDRs)
```bash
Get-AppLockerPolicy # Display details on what/if AppLocker policies are set.
Get-MpComputerStatus # Display Windows Defender status.

Get-AppLockerPolicy -Effective | 
	select -ExpandProperty RuleCollections

Get-AppLockerPolicy -Local | 
	Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```

AppLocker only applies to Exe's, DLLs, Wmi's and scripts.

## Initial Enumeration
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands

#### Key Data points

- OS name 
- $PSVersionTable
- systeminfo
- tasklist /svc

> Become familiar with standard windows processes:
> 	- Session manager Subsystem (smss.exe)
>	- Client Server Runtime Subsystem (csrss.exe)
>	- WinLogon (winlogon.exe)
>	- Local Security Authority Subsystem Service (LSASS)
>	- Service Host (svchost.exe)

Non-Standard services are a potentional vector, considering.

Some processes like `MsMpEng.exe` (Windows Defender) may help us map out what protections
are in place on the system that we might have to watch out for. 

- PATH Variables, especially non-standard ones, 
	if we have write privileges for that particular path.
	It could allow us to perform DLL injections,
	Or attacking Unquoted Service Paths.

- Order of Operations for Windows Path Searching starts from CWD then going left to right.
- `set` can give helpful info such as HOME DRIVE.

#### Viewing Detailed Config Information

- `systeminfo` # will show patching/VM information.
- `hotfix catalog`: # https://www.catalog.update.microsoft.com/Search.aspx?q=hotfix
- `wmic qfe`: # list applied patches with WMI
- `Get-HotFix | ft -AutoSize`

#### Installed Programs

- `wmic product get name` # Display installed software
- `Get-WmiObject -Class Win32_Product | select Name, Version`

#### Display Network Connections

- `netstat -ano`
- `Get-NetTCPConnection`

#### Logged-In Users

- `query user`
- `whoami`
- `echo %USERNAME%`
- `whoami /priv`
- `whoami /groups`
- `net user`
- `net localgroup <group_name>`
- `net accounts`
- `accesschk 'administrator' -a *`

## Communication with Processes

localhost connections are often overlooked. Just food for thought.

#### Named Pipes

- `pipelist.exe /accepteula`
- `Get-ChildItem \\.\pipe\`

Pipes are esentially files stored in memory that get cleared after reading.
The CobalStrike named pipe workflow:
```
	- Beacon starts a named pipe of \.\pip\msagent_10
	- Beacon starts a new process and injects command, directing stdout to pipe.
	- Server receives the pip message.
```

- `accesschk.exe /accepteula \\.\pipe\lsass -v` # Check named pipe permissions.
- `accesschk.exe -accepteula -w \pipe\WindscribeService -v` # "RW EVERYONE/ FILE_ALL_ACCESS"

## System Information

- `tasklist /svc`
- `set ${ENV_VARIABLE}`