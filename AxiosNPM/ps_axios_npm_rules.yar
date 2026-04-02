rule axios_supply_chain_attk_dns_request
{
    meta:
		
      description = "Detect domain used in the axios supply chain attack"
	  reference   = "https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package"
      filter      = "Frames (frames:)"
	  sha1        = "978407431d75885228e0776913543992a9eb7cc4"
      author      = "Netomize"
      date        = "04/02/2026"
	
    condition:
		
	  dns.is_set and not dns.over_tcp and not dns.flag.response 
	  and
	  dns.flag.opcode   == 0 
	  and
	  dns.count.queries == 1
	  and
	  dns.qry[0].type   == 1  // A
	  and
	  dns.qry[0].class  == 1  // IN
	  and
	  // sfrclak.com
	  dns.qry[0].name.qname == "sfrclak.com"
}

rule axios_supply_chain_attk_downloader_header
{
    meta:
	
      description = "Detect POST request used to download 2nd stage RAT used in the Axios supply chain attack"
	  reference   = "https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package"
      filter      = "Frames (frames:)"
	  sha1        = "978407431d75885228e0776913543992a9eb7cc4"
      author      = "Netomize"
      date        = "04/02/2026"

	strings:
	
	  $post      = "POST " // early exit
	  $http_line = /POST [^\r\n]{0,84}\/\d{0,14} HTTP\/1\.[01]\r?\n/		
	  $ctype_hdr = "\x0aContent-Type: application/x-www-form-urlencoded" nocase
	  $clen_hdr  = /\nContent-Length: 2[4-9]\r?\n/i

    condition:

	  tcp.is_set
	  and
	  flow.to_server
	  and
	  math.in_range(port.src, 1024, 65535) // ephemeral ports	  
	  and
	  ip.dst.type == 1
	  
	  and
	  
	  with buff = tcp.data.offset, buff_sz = tcp.data.size :
		(
			buff_sz > 200 and buff_sz < 500
			and
			$post at buff
			and
			$http_line at buff
			and
			$ctype_hdr in (buff + 16..buff + 16 + buff_sz)
			and
			$clen_hdr  in (buff + 16..buff + 16 + buff_sz)
		)
}

rule axios_supply_chain_attk_downloader_body
{
    meta:
	
      description = "Detect POST request used to download 2nd stage RAT used in the Axios supply chain attack"
	  reference   = "https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package"
      filter      = "Frames (frames:)"
	  sha1        = "978407431d75885228e0776913543992a9eb7cc4"
      author      = "Netomize"
      date        = "04/02/2026"

	strings:
	
	  $body = /packages\.npm\.org\/product\d{0,6}$/

    condition:

	  tcp.is_set
	  and
	  flow.to_server
	  and
	  math.in_range(port.src, 1024, 65535) // ephemeral ports
	  and
	  ip.dst.type == 1
	  
	  and
	  
	  with buff = tcp.data.offset, buff_sz = tcp.data.size :
		(
			buff_sz > 23 and buff_sz < 500
			and
			$body in (buff..buff + buff_sz)
		)		
}

rule axios_supply_chain_rat_data_exfil_post_body
{
    meta:
	
      description = "Detect exfiltrated data sent by the 2nd stage RAT used in the Axios supply chain attack"
	  reference   = "https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package"
      filter      = "Frames (frames:)"
	  sha1        = "978407431d75885228e0776913543992a9eb7cc4"
      author      = "Netomize"
      date        = "04/02/2026" 

	strings:
	
	  $sz_bytes  = "\"SizeBytes\"" base64
	  $childs    = "\"childs\":"   base64
	  $isdir     = "\"IsDir\""     base64
	  $parent    = "\"parent\":"   base64
	  $has_items = "\"HasItems\":" base64
	  $modified  = "\"Modified\":" base64
		
    condition:
		
	  tcp.is_set
	  and
	  flow.to_server
	  and
	  tcp.data.size > 300
	  and
	  math.in_range(port.src, 1024, 65535) // ephemeral ports	  
	  and
	  ip.dst.type == 1	  
	  and
	  all of them
}