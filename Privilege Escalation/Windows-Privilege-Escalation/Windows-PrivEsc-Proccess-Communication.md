# Communication with Processes

- Access Tokens describe the security context of a process/thread
- Token includes information about the user account's identity/privileges

## Enumerating Network Services

Display active connections:

- `netstat -ano`

- Named Pipes are another comms method for processes.
- If the command being ran gets flagged, it will close the pipe but not the proccess.
- Windows use a client-server implementation. Server, being the creator of the pipe.

`pipelist.exe /accepteula`
`gci \\.\pipe\`
`accesschk.exe /accepteula \\.\pipe\lsass -v`
`accesschk.exe /accepteula -w \pipe\WindescribeService -v`
