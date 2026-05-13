rule crushftp_auth_bypass_vulnerability_get_req_cve_2025_31161
{
    meta:
	
      description = "Detect authentication bypass request in CrushFTP server (CVE-2025-31161)"
	  reference   = "https://outpost24.com/blog/crushftp-auth-bypass-vulnerability/"
      filter      = "Frames (frames:)"
      author      = "Netomize"
      date        = "13/05/2026"
	  track_state = "set,crushftp_auth_bypass,noalert"

	strings:
	
		$uri               = "GET /WebInterface/function/"
		
		$cookie_curr_auth  = /\nCookie:[^\r\n]{0,256}currentAuth=\w{4}[;\r\n]/i
		$cookie_crush_auth = /\nCookie:[^\r\n]{0,256}CrushAuth=\w{31}/i
		$authorization     = /\nAuthorization:[^\r\n]{0,256}AWS4-HMAC-SHA256 Credential=[^~\r\n\/]{1,255}\//i
	
    condition:

	  tcp.is_set
	  and 
	  tcp.data.size > 156
	  and 
	  flow.to_server
	  and
      with buf_off = tcp.data.offset, buf_sz = tcp.data.size:
	  	(
			$uri at buf_off
			and
			$cookie_curr_auth  in (buf_off + 36..buf_off + 36 + buf_sz)
			and
			$cookie_crush_auth in (buf_off + 36..buf_off + 36 + buf_sz)
			and
			$authorization     in (buf_off + 36..buf_off + 36 + buf_sz)
	  	)
}

rule crushftp_rce_vulnerability_post_req_cve_2025_31161
{
    meta:
	
      description = "Detect rce POST request in CrushFTP server (CVE-2025-31161)"
	  reference   = "https://outpost24.com/blog/crushftp-auth-bypass-vulnerability/"
      filter      = "Frames (frames:)"
      author      = "Netomize"
      date        = "13/05/2026"
	  track_state = "isset,crushftp_auth_bypass,alert"

	strings:
	
		$uri               = "POST /WebInterface/function/"
		
		$cookie_curr_auth  = /\nCookie:[^\r\n]{0,192}currentAuth=\w{4}[;\r\n]/i
		$cookie_crush_auth = /\nCookie:[^\r\n]{0,192}CrushAuth=\w{31}/i
		$authorization     = /\nAuthorization:[^\r\n]{0,256}AWS4-HMAC-SHA256 Credential=[^~\r\n\/]{1,255}\//i
	
    condition:

	  tcp.is_set
	  and 
	  tcp.data.size > 156
	  and 
	  flow.to_server
	  and		
      with buf_off = tcp.data.offset, buf_sz = tcp.data.size:
	  	(
			$uri at buf_off
			and
			$cookie_curr_auth  in (buf_off + 36..buf_off + 36 + buf_sz)
			and
			$cookie_crush_auth in (buf_off + 36..buf_off + 36 + buf_sz)
			and
			$authorization     in (buf_off + 36..buf_off + 36 + buf_sz)
	  	)
}