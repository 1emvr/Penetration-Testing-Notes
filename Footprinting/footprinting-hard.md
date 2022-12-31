# footprinting - hard lab - HackTheBox
---

IMAP/POP3:
	- commonName=NIXHARD
	- No organization name

```bash
	110/tcp open  pop3     Dovecot pop3d

|_pop3-capabilities: SASL(PLAIN) USER STLS TOP UIDL AUTH-RESP-CODE CAPA RESP-CODES PIPELINING
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25

143/tcp open  imap     Dovecot imapd (Ubuntu)

|_imap-capabilities: more ID SASL-IR post-login OK LITERAL+ LOGIN-REFERRALS have listed capabilities ENABLE AUTH=PLAINA0001 Pre-login IMAP4rev1 STARTTLS IDLE
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_ssl-date: TLS randomness does not represent time

993/tcp open  ssl/imap Dovecot imapd (Ubuntu)

|_imap-capabilities: ID SASL-IR more OK LITERAL+ LOGIN-REFERRALS have post-login listed ENABLE AUTH=PLAINA0001 capabilities IMAP4rev1 Pre-login IDLE
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_ssl-date: TLS randomness does not represent time

995/tcp open  ssl/pop3 Dovecot pop3d

|_pop3-capabilities: UIDL AUTH-RESP-CODE CAPA USER RESP-CODES PIPELINING TOP SASL(PLAIN)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- SNMP port found (udp 161)
- SNMP-Brute:
```bash
	PORT    STATE SERVICE VERSION
161/udp open  snmp    net-snmp; net-snmp SNMPv3 server
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 5b99e75a10288b6100000000
|   snmpEngineBoots: 10
|_  snmpEngineTime: 47m09s
```

- used OneSixtyOne tool to enumerate SNMP service to find community name.
- found community name [backup]
- found credenitals in the SNMPWalk output: "tom NMds732Js2761"
- logged into SMTP/IMAP using credentials with Thunderbird. Found an SSH private key.
- "Tom is not allow to run sudo on NIXHARD"
- Discovered MySQL database running on localhost. Got credentials "HTB:cr3n4o7rzse7rzhnckhssncif7ds"
