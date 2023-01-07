## Application Configuration Files

#### Searching for Files

![[Pasted image 20230107153225.png]]

Applications often store passwords in cleartext config files. Sensitive IIS information such as
credentials may be stored in a `web.config` file. For the default IIS website, this could be located
at `C:\inetpub\wwwroot\web.config` but there may be multiple versions in different locations.

## Dictionary Files

#### Chrome Dictionary Files

Sensitive information may be entered in an email client or browser-based application, which 
underlines unrecognized words. The user can add these words to their dictionary for autocomplete.

```powershell-session
PS C:\htb> gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password

Password1234!
```

#### Unattended Installation Files

Unattended.xml
```xml
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <AutoLogon>
                <Password>
                    <Value>local_4dmin_p@ss</Value>
                    <PlainText>true</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <LogonCount>2</LogonCount>
                <Username>Administrator</Username>
            </AutoLogon>
            <ComputerName>*</ComputerName>
        </component>
    </settings>
```

## PowerShell History File
`C:\Users\username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`.

#### Confirming PowerShell History Save Path

![[Pasted image 20230107154047.png]]

#### Reading PowerShell History File

![[Pasted image 20230107154121.png]]

Also, a  one-liner to retreive the contents of Powershell history as current user.

This can be extremely helpful as a post-exploitation step. We should always check these files once
we have local admin if our prior access did not allow us to read these files for some users.

This command assumes that the default save path is being used.

```powershell-session
PS C:\htb> foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}

dir
cd Temp
md backups
cp c:\inetpub\wwwroot\* .\backups\
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://www.powershellgallery.com/packages/MrAToolbox/1.0.1/Content/Get-IISSite.ps1'))
. .\Get-IISsite.ps1
Get-IISsite -Server WEB02 -web "Default Web Site"
wevtutil qe Application "/q:*[Application [(EventID=3005)]]" /f:text /rd:true /u:WEB02\administrator /p:5erv3rAdmin! /r:WEB02
```

## PowerShell Credentials

![[Pasted image 20230107155133.png]]

#### Decrypting PowerShell Credentials

If we have gained command execution in the context of this user or can abuse DPAPI, then we can
recover the cleartext credentials from `encrypted.xml`.

![[Pasted image 20230107155339.png]]

