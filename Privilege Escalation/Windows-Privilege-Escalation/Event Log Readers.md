Audit Process Creation is enabled. Information is saved to the Windows security event log 
as `event ID 4688: A new process has been created`.

A study showing some of the most commonly run commands by attackers:
https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html

Fine-tuned AppLocker rules can be set to prevent users from performing some of these cmds.
The security team could also monitor these commands and who's running them.

##### Confirming Group Membership & Searching Security Logs

![[Pasted image 20230107145144.png]]

#### Search Security Logs with wevtutil

![[Pasted image 20230107145247.png]]

#### Passing Other Credentials

![[Pasted image 20230107145302.png]]

##### Using Get-WinEvent

Note: Searching the Security event log with Get-WinEvent requires administrator access or 
permissions adjusted on the registry key:
	
			  `HKLM\System\CurrentControlSet\Services\Eventlog\Security`

Membership in the Even Log Readers Group is not sufficient.
```
Get-WinEvent -LogName security |
	where {$_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} |
		Select-Object @{name='CommandLine';expression={$_.Properties[8].Value}}
```

