# Protected File Transfers

On Windows:

Invoke-AESEncryption.ps1
```ps
function Invoke-AESEncryption {

	[CmdletBinding()]
	[OutputType([string])]

	Param
	(
		[Parameter(Mandatory = $true)]
		[ValidateSet('Encrypt', 'Decrypt')]
		[String]$Mode,

		[Parameter(Mandatory = $true)]
		[String]$Key,

		[Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
		[String]$Text,

		[Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
	)

	Begin {
		$shaManaged = New-Object System.Security.Cryptography.SHA256Managed
		$aesManaged = New-Object System.Security.Cryptography.AesManaged
		$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
		$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
		$aesManaged.BlockSize = 128
		$aesManaged.KeySize = 256
	}

	Process {
		$aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

		switch ($Mode) {

			'Encrypt' {
				if ($Text) {
					$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
				}
				if ($Path) {
					$File = Get-Item -Path $Path -ErrorAction SilentlyContinue
					if (!$File.FullName) {
						Write-Error -Message "File not found!"
						break
					}
					$plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
					$outPath = $File.FullName + ".aes"
				}

				$encryptor = $aesManaged.CreateEncryptor()
				$encryptedBytes = $encryptor.TransformFinalBlock(
					$plainBytes, 0,	$plainBytes.Length
					)
				$encryptedBytes = $aesManaged.IV + $encryptedBytes
				$aesManaged.Dispose()

				if ($Text) {
					return [System.Convert]::ToBase64String($encryptedBytes)
				}

				if ($Path) {
					[System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
					(Get-Item $outPath).LastWriteTime = $File.LastWriteTime
					return "File encrypted to $outPath"
				}
			}

			'Decrypt' {
				if ($Text) {
					$cipherBytes = [System.Convert]::FromBase64String($Text)
				}

				if ($Path) {
					$File = Get-Item -Path $Path -ErrorAction SilentlyContinue
					if (!$File.FullName) {
						Write-Error -Message "File not found!"
						break
					}
					$cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
					$outPath = $File.FullName -replace ".aes"
				}

				$aesManaged.IV = $cipherBytes[0..15]
				$decryptor = $aesManaged.CreateDecryptor()
				$decryptedBytes = $decryptor.TransformFinalBlock(
					$cipherBytes, 16, $cipherBytes.Length - 16
					)
				$aesManaged.Dispose()

				if ($Text) {
					return [System.text.Encoding]::UTF8.GetString(
						$decryptedBytes).Trim([char]0)
				}
				if ($Path) {
					[System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
					(Get-Item $outPath).LastWriteTime = $File.LastWriteTime
					return "File decrypted to $outPath"
				}
			}
		}
	}

	End {
		$shaManaged.Dispose()
		$aesManaged.Dispose()
	}
}
```

Import the module and then:
```
PS C:\> Invoke-AESEncryption -Mode Encrypt -Key "password123" -Path .\RandomGayShit.txt

File encrypted to C:\RandomGayShit.txt.aes
```

# Nginx -Enabling PUT

A good alternative for transfering files to Apache is `Nginx` because the configuration 
is less complicated and the module system does not lead to security issues as Apache can.

When allowing HTTP uploads it's critical to be 100% positive that users 
cannot upload web shells and execute them. Apache makes it easy to shoot ourselves 
in the foot with this as the PHP module loves to execute anything ending with .php. 

Configuring Nginx to use PHP is nowhere near as simple...

## Create a Directory to handle uploaded files
```bash
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```

## Create Nginx Config File
```bash
/etc/nginx/sites-available/upload.conf:

server {
	listen 9001;

	location /SecretUploadDirectory/ {
		root	/var/www/uploads;
		dav_methods PUT;
	}
}
```

## Symlink our Site to the sites-enabled Directory
```bash
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled
sudo systemctl restart nginx.service
```

## Verifying Errors
```bash
tail -2 `/var/log/nginx/error.log`
ss -lnpt | grep <port-number>
ps -ef | grep <conflicting-process-number>
```

## Remove NginxDefault Config
```bash
sudo rm /etc/nginx/sites-enabled/default
```

Now we can test uploading by using cURL to send a PUT request.
```bash
curl -T /etc/passwd http://localhost:9001/Secret/users.txt
```
