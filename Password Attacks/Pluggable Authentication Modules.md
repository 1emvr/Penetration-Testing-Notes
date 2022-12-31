# Pluggable Authentication Modules

Linux-based distributions can use many different authentication mechanisms. One of the most commonly used and 
standard mechanisms is PAM. The modules used for this are called `pam_unix.so` or `pam_unix2.so` and are located in 
`/usr/lib/x86_64-linux-gnu/security` in Debian based distributions. 

These modules manage user information, authentication, sessions, current passwords and old passwords. For example, 
if we want to change the password of our account on the Linux system with `passwd`, PAM is called, which takes the 
appropriate precautions and stores and handles the information accordingly.

The `pam_unix.so` standard module for management uses standardized API calls from the system libraries and files to 
update the account information. The standard files that are read, managed and updated are `/etc/passwd` and `/etc/
shadow`. PAM also has many other service modules usch as LDAP, mount or Kerberos.

If you clear the password field for a user in `/etc/passwd` you will no longer be prompted for a password. :)

# Shadow File

Since reading the password hash values can put the entire system in danger, the file `/etc/shadow` was developed, 
which has a similar format to /etc/passwd but is only responsible for passwords and their management. 

It contains all the password information for the created users. For example, if there is no entry in the /etc/
shadow file for a user in /etc/passwd, the user is considered invalid. The /etc/shadow file is also only readable 
by users who have administrative rights. The format of this file is divided into nine fields:

`Username:EncryptedPassword:LastPWChange:MinPWAge:MaxPWAge:WarningPeriod:InactivityPeriod:ExpirationDate:Unused`

If the password field contains a character, such as `!` or `*`, the user cannot login with a Unix password. 
However, other authentication methods for logging in, such as Kerberos or key-based authentication can still be 
used. The same case applies if the encrypted password field is empty. This means that no password is required for 
login. However, it can lead to specific programs denying access to functions. The encrypted password also has a 
particular format by which we can also find out some information:

`$<type>$<salt>$<hashed>`

As we can see here, the encrypted passwords are divided into three parts. 
The types of encryption allow us to distinguish between the following:

## Algorithm Types

- $1$ : MD5
- $2a$ : Blowfish
- $2y$ : Eksblowfish
- $5$ : SHA-256
- $6$ : SHA-512

# Opasswd

The PAM library `(pam_unix.so)` can prevent reusing old passwords. The files where old passwords are stored is the 
`/etc/security/opasswd`. Administrator/root permissions are also required to read the file if the permissions for 
this file have not been changed manually.

