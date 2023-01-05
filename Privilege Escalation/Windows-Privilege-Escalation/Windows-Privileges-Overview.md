# Windows Privileges Overview
https://academy.hackthebox.com/module/67/section/624

## Windows Authorization Process

```
Subject (User)							Object (File or Folder)
==============							=======================

User's Access Token						Object's Security Descriptor
-------------------						----------------------------
User SID								Object Owner SID
Group SIDs		--1.Access Check-->		Group SIDs
Privileges								SACL/ACEs --------> 2.Examine each ACE until match.
Extra Access Info						DACL/ACEs --------> 3.Access decision is made.
```

## Rights and Privileges in Windows

- Groups

- `Default Administrators`: Domain/Enterprise Admins are "super" groups
- `Server Operators`: Members can modify services, access SMB shares and backup files
- `Backup Operators`: Allowed to log onto DCs locally and should be considered Domain Admins
- `Print Operators`: Allowed to log onto DCs locally and "trick" Windows to load malicious drivers
- `Hyper-V Admins`: If there are virtual DCs should be considered Domain Admins
- `Account Operators`: Allowed to modify non-protected accounts and groups
- `RDP Users`: Allowed login through RDP and can move laterally using RDP
- `Remote Management`: Allowed to log onto DCs with PSRemoting
- `Group Policy Creator Owners`: Allowed to create new GPOs but 
	need delegated extra permissions to link GPOs to containers such as Domain or OU

- `Schema Admins`: Allowed to modify AD Schema structure and backdoor any to-be-created gropu/GPO
- `DNS Admins`: Allowed to load a DLL on DC but don't have permission to restart DNS server.

## User Rights Assignment

`whoami /priv`

- `SeNetworkLogonRight`: Remote connect device required by SMB, NetBIOS, CIFS and COM+
- `SeRemoteInteractiveLogonRight`: Access login screen of remote device through RDP
- `SeBackupPrivilege`: Rights to bypass file and directory/registry/persistent obj permissions
- `SeSecurityPrivilege`: Specify obj access audit options for files, objs and reg keys
- `SeTakeOwnershipPrivilege`: Ability to take ownership of securable objects
- `SeDebugPrivilege`: Can attach to or open any process.
- `SeImpersonatePrivilege`: Impersonate another user/service account
- `SeLoadDrivePrivilege`: Can dynamically load/unload device drivers
- `SeRestorePrivilege`: Can bypass file/directory/registry permissions when restoring backups

https://4sysops.com/archives/user-rights-assignment-in-windows-server-2016/
https://www.leeholmes.com/adjusting-token-privileges-in-powershell/
https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts%5CEnable-Privilege.ps1


## SeImpersonate and SeAssignPrimaryToken

`CreateProcessWithTokenW`: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw

