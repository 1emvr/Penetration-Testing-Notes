# DNS Footprinting

```bash
bluechat@htb[/htb]$ dig ns inlanefreight.htb @10.129.14.128
bluechat@htb[/htb]$ dig any inlanefreight.htb @10.129.14.128

bluechat@htb[/htb]$ dig axfr inlanefreight.htb @10.129.14.128
bluechat@htb[/htb]$ dig axfr internal.inlanefreight.htb @10.129.14.128

```

## Subdomain Bruteforcing

```bash
for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
bluechat@htb[/htb]$ dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```