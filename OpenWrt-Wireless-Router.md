- Everything is in /etc/config
- cp firewall firewall.original
- cp network network.original
- cp wireless wireless.original
- vi network

	config interface 'lan'
		option device	'br-lan'
		option proto	'static'
		optioni ipaddr	'x.x.x.x'
		option netmask	'x.x.x.x'
		option ip6assign	'60'
		option force_link	'1'

	config interface 'wwan'
		option proto	'dhcp'
		option peerdns	'0'
		option dns		'1.1.1.1 1.0.0.1'

	config interface 'vpnclient'
		option ifname	'tun0'
		option proto	'none'

- vi firewall

	config zone
		option name		'wan'
		option input	ACCEPT

- reboot

- vi wireless

	config wifi-device 'radio0'
		option channel		'7'
		option hwmode		'11g'
		option htmode 		'HT20'
		option disabled		'0'
		option short_gi_40	'0'

- uci commit wireless
- wifi

- visit Luci UI
- Network -> Wireless -> Scan for networks
- Check Replace Wireless Configuration
