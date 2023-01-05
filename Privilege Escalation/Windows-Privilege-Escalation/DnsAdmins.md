The Windows DNS service supports custom plugins and can call functions from them to resolve
name queries that are not in the scope of any locally hosted DNS zones.

The DNS service runs as `NT AUTHORITY\SYSTEM`. Membership in this group could potentially be
leveraged to escalate privileges on the DC or in a situation where a separate server is acting
as the DNS server for the domain.

