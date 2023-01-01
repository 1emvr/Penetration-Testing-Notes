# Kerberos Fundamentals

- PAC: Privilege Attritube Certificate: Contains all the relevant user information:
```
- Account Name
- Group RID (used in SID value creation)
- Group Membership Array (Security membership/Access Rights)
- PAC_SERVER_CHECKSUM
- PAC_PRIVSVR_CHECKSUM
```

Protect the PAC signing with two signatures
using it's own password hash as the key. Service account password hash and KDC's hash.

- Service Ticket: 
```
Server portion:
- User details
- Session key
- Encrypted with Service Account NTLM Hash

User portion:
- TTL
- Session Key
- Encrypted with TGT Session Key
```

- Service Principal Name: Links service account to services
```
- KDC Long-term Secret Key (derived from KRBTGT account password)
  Used to encrypt the TGT (AS-REP) and signing the PAC (AS-REP AND TGS-REP)
  
 - Client Long-term Secret Key (derived from clilent account password)
  Used to check encrypted timestamp (AS-REQ) and encrypt session key (AS-REP)
  
  - Target Service Long-term Secrety Key (derived from service account password)
    Used to encrypt service portion of the ST (TGS-REP) and sign the PAC (TGS-REP)
    
 proxym\lemur:password -> rc4_hmac_md5 -> AS-REQ -> AS-REP/TGT -> TGS-REQ -> TGS-REP -> TGS(ST)
```

```
 TGT - Encrypted using KDC LT Key (KRBTGT NT hash)
 
 Start/ End/ MaxRenew:
 Service Name:
 Target Name:
 Client Name:
 Flags:
 Session Key:
 
 Privilege Account Certificate (PAC)
 Username: lemur
 SID S-I-5-21-409...SNIP...
 
 Signed using Target LT Key
 Signed using KDC LT Key
```
 
 ## TGT and PAC
 
 AS-REQ with Pre-Authentication
 - The user will use their NT hash to encrypt a timestamp, sending to AS (Authentication Server)
 - The KDC attempts to decrypt the timestamp using User's NT hash. 
 - If successful, TGT (encrypted using krbtgt NTLM hash) and client/TGS (encrypted using password hash) are returned.
 
```
 Service Ticket (TGS)
 
 Client Portion:
  - Validity time of the ticket
  - Session Key
  
 Server Portion:
  - Encrypted
  
 Privilege Account Certificate (PAC)
 Username: lemur
 SID S-I-5-21-409...SNIP...
 
 Signed using Target LT Key
 Signed using KDC LT Key
```
 ## PAC Validation
 
 When target service receives the server portion of Service Ticket, 
 it can read contents of the PAC but it's not always validated.
  
  - For TGT: PAC is only validated when the TGT is more than 20 minutes old.
  - For TGS: PAC is typically validated for services on modern Windows.

## Golden Ticket Attack - Forged TGT

To create a valid TGT (with valid PAC):
  - The Target LT Key
  - The KDC LT Key

In TGT, these keys are identical (krbtgt). Then obtain NTLM hash of the krbtgt account (RC4) or AES Key.

- Ticket Flow: `TGS-REQ Using forged TGT with no prior credential submission or AS-REQ/AS-REP`
- No interaction with the DC. Kerberos is "stateless" and does not track creation of tickets.
- Requires KDC Long Term Key.
- Using Mimikatz, can be generated using:

  - KDC LT Key (KRBTGT NTLM Hash)
  - Domain Admin Account Name
  - Domain Name
  - SID of Domain Admin Account

  - Re-inject the ticket in Windows memory

KRBTGT NTLM is very sensitive. If something goes wrong, the entire domain could be fucked. You've ruined everything.

## Skeleton Key

- Only works for Kerberos RC4 encryption
- Is a backdoor that runs on the Domain Controller (in memory) allows single password for all accounts
- Also potentially dangerous

## Kerberoasting

- The ST from the TGS-REP is encrypted using the service account's password
- KDC Doesn't verify our permission to access the service. Only the tickets.
- Crack the service account's password

Mimikatz supports this but evasion can be an issue. `Invoke-Mimikatz` from PowerSploit/Empire

## Silver Ticket

Service Tickets are encrypted and signed using the service acocunt password.
If we get this hash (or password), we can generate a new ticket, bypassing the KDC for a TGS.

KRBTGT NTLM is not necessary and is a lot more quiet:

  - Forge a Service Ticket with custom PAC using Target LT Key (Service NTLM)
  - If PAC Validation is disabled then we are finished! If it's enabled, it won't work.
