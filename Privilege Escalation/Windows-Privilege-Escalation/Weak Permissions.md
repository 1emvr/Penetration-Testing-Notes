#### Permissive File System ACLs

SharpUp from the GhostPack suite can check for service binaries w/ weak permissions

![[Pasted image 20230107100854.png]]

The tool identifies the PC Security Management Service, which executes the `SecurityService.exe`

#### Checking Permissions with icacls

Using icacls we can verify the vulnerability and see that the `EVERYONE` and `BUILTIN\Users` groups
have been granted full permissions to the directory.

![[Pasted image 20230107101145.png]]

#### Replacing Service Binary

The service is also startable by unprivileged users. We can make a backup of the original binary
and replace it with a malicious binary generated with msfvenom.

![[Pasted image 20230107101620.png]]

## Weak Service Permissions

#### Reviewing SharpUp Again

![[Pasted image 20230107101928.png]]

#### Checking Permissions with AccessChk

![[Pasted image 20230107102139.png]]

#### Check Local Admin Group

Our user is confirmed `not a member` of adminsitrators group:

![[Pasted image 20230107102343.png]]

#### Changing the Service Binary Path

We can use our permissions to change the binary path maliciously, adding to local admin group.

![[Pasted image 20230107102539.png]]

#### Stopping/Starting Service

![[Pasted image 20230107102558.png]]

![[Pasted image 20230107102609.png]]

