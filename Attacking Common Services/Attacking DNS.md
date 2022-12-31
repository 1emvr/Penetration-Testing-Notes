# Attacking DNS

## DNS Zone Transfer

```bash
bluechat@htb[/htb]# dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
bluechat@htb[/htb]# fierce --domain zonetransfer.me
bluechat@htb[/htb]# ./subfinder -d inlanefreight.com -v
bluechat@htb[/htb]$ ./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
```

`Domain Takeovers` is registering non-existent domain names to gain control over another. If we find an expired domain, we can claim that domain to perform further attacks such as hosting malicious content on a website or sending a phishing email.

A DNS's canonical name `(CNAME)` record is used to map different domains to a parent. Many companies use third-party services like AWS, Github, Akamai, Fastly and other CDNs to host their content. In this case, they usually create a subdomain and make it point to those services.

https://github.com/EdOverflow/can-i-take-over-xyz

## DNS Spoofing

Typically proctoring with a MITM attack
or Exploiting a vuln found in a DNS server

### Local DNS Cache Poisoning

```bash
bluechat@htb[/htb]# cat /etc/ettercap/etter.dns

inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

Start `Ettercap` and scan for Hosts > Scan for Hosts, add victim to Target 1 and default gateway to Target 2
Activate `dns_spoof` with `Plugins > Manage Plugins`.