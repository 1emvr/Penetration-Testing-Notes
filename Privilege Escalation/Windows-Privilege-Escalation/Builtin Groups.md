Privileged Accounts & Groups in AD:
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory

- Backup Operators group
- Event Log Readers group
- DnsAdmins group
- Hyper-V Administrators group
- Print Operators group
- Server Operators group

### Backup Operators Group

`whoami /groups` shows our groups membership.
Members of this group inherit `SeBackup` and `SeRestore` privileges.

`SeBackupPrivilege` allows us to traverse any folder and list the folder contents.
This let's us copy a file from the folder, even if there's no ACE for us in the folder's ACL.

We need to programmatically copy the data, making sure to specify `FILE_FLAG_BACKUP_SEMANTICS`.

#### Importing Libraries

![[Pasted image 20230107135205.png]]

#### Verifying SeBackupPrivilege is Enabled

![[Pasted image 20230107135235.png]]

![[Pasted image 20230107135250.png]]

#### Enabling SeBackupPrivilege

![[Pasted image 20230107135326.png]]

#### Copying Protected Files

![[Pasted image 20230107135506.png]]

![[Pasted image 20230107135538.png]]

### Attacking a Domain Controller - Copying NTDS.dit

With the backup permission, we can log into a DC locally. We can create a shadow copy:

![[Pasted image 20230107135630.png]]

#### Copying NTDS.dit Locally

![[Pasted image 20230107135659.png]]

### Backup up SAM and SYSTEM

![[Pasted image 20230107135729.png]]

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

![[Pasted image 20230107135913.png]]