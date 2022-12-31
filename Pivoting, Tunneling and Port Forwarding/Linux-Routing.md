# Routing

- Using Linux as a router, we can forward incoming traffic to our OpenVPN connection

```bash
sudo echo 1 > /proc/sys/net/ipv4/ip_forward
sudo sysctl -a | grep ip_forward

sudo iptables -A FORWARD -i tun0 -o eth0 -m state --state RELATED,ESTABLISHED -j accept
sudo iptables -A FORWARD -i eth0 -o tun0 -j ACCEPT

sudo iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o tun0 -j MASQUERADE
```

```
Windows VM:
route add 10.10.10.0 mask 255.255.255.0 192.168.1.123
ping 10.10.10.2
```
