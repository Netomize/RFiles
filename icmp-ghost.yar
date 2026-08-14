import "math"

rule icmp_ghost_implant_icmp_echo_request_c2_detection
{ 
	meta:
	
	  description = "Detect ICMP-Ghost ICMP Echo Request C2 Traffic"
	  reference   = """https://github.com/JM00NJ/ICMP-Ghost-A-Fileless-x64-Assembly-C2-Agent
					           https://netacoding.com/posts/icmp-ghost/
                     https://blog.netomize.ca/detect-icmp-ghost-implant-icmp-and-dns-tunnelling-c2-traffic-using-packetsmith-yara-x-icmp-detection-modules
	                """
	  filter      = "Frames (frames:)"
	  author      = "Netomize"
	  date        = "08/11/2026"
	  
	strings:
	
	  $padding = { 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f }

	condition:

	  ip4.is_set and not ip4.in_ip6
	  and
	  icmp4.is_set and icmp4.type == 0x08 and icmp4.code == 0x00	  
	  and
	  with ident_num = uint16be(icmp4.data.offset), seq_num = uint16be(icmp4.data.offset+2), 
	       idata = icmp4.data.offset + 4, isize = icmp4.data.size :
	  (
	    // data is rolling XOR encrypted
	    isize >= 28 + 56 // (28 -> ident, seq, rdtsc value and the padding bytes) + (56 -> chunk size)
		and
		math.in_range(ident_num, 10000, 29999) 
		and
		math.in_range(seq_num, 15001, 35000) 
		and
		(ident_num + seq_num == 45000) // asymmetric authentication
		and
		uint32be(idata + 4) == 0x00000000 // rdtsc high 32-bits
		and
	    $padding at (idata + 8) // + 8 -> skipping over the rdtsc value
	  )
}

rule icmp_ghost_implant_icmp_echo_reply_ctrl_cmd_c2_detection
{ 
	meta:
	
	  description = "Detect ICMP-Ghost ICMP Echo Reply C2 control command traffic"
	  reference   = """https://github.com/JM00NJ/ICMP-Ghost-A-Fileless-x64-Assembly-C2-Agent
					           https://netacoding.com/posts/icmp-ghost/
                     https://blog.netomize.ca/detect-icmp-ghost-implant-icmp-and-dns-tunnelling-c2-traffic-using-packetsmith-yara-x-icmp-detection-modules
	                """
	  filter      = "Frames (frames:)"
	  author      = "Netomize"
	  date        = "08/11/2026"
	  
	strings:
	
	  $padding = { 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f }

	condition:

	  ip4.is_set and not ip4.in_ip6
	  and
	  icmp4.is_set and icmp4.type == 0x00 and icmp4.code == 0x00	  
	  and
	  with ident_num = uint16be(icmp4.data.offset), seq_num = uint16be(icmp4.data.offset+2), 
	       idata = icmp4.data.offset + 4, isize = icmp4.data.size :
	  (
	    isize > 28 + 10 // data is rolling XOR encrypted and VESQER compressed
		and
		math.in_range(ident_num, 10000, 29999) 
		and
		math.in_range(seq_num, 25001, 45000)
		and
		ident_num + seq_num == 55000 // asymmetric authentication
		and
		uint32be(idata + 4) == 0x00000000 // rdtsc high 32-bits
		and		
	    $padding at (idata + 8) // + 8 -> skipping over the rdtsc value
	  )
}


rule icmp_ghost_implant_dns_query_c2_detection
{
    meta:
	
      description = "Detect ICMP-Ghost DNS Query C2 control command traffic"
	    reference   = """https://github.com/JM00NJ/ICMP-Ghost-A-Fileless-x64-Assembly-C2-Agent
					             https://netacoding.com/posts/icmp-ghost/
                       https://blog.netomize.ca/detect-icmp-ghost-implant-icmp-and-dns-tunnelling-c2-traffic-using-packetsmith-yara-x-icmp-detection-modules
	                  """	  
      filter      = "Frames (frames:)"
      author      = "Netomize"
      date        = "08/11/2026"
	  		
    condition:
	
	udp.is_set and dns.is_set	
	and 
	((dns.id >> 8) + (dns.id & 0xff)) == 0xff // asymmetric authentication
	and 
	not dns.flag.response 
	and 
	dns.flag.opcode == 0
	and 
	not dns.flag.truncated 
	and 
	dns.flag.recdesired 
	and 
	not dns.flag.z
	and 
	not dns.flag.authenticated
	and
	dns.count.queries == 1
	and
	dns.count.ansr_rr == 0
	and
	dns.count.auth_rr == 0
	and
	dns.count.addi_rr == 0
	and
	// Type: A (1) (Host Address); Class: IN (0x0001)
	dns.qry[0].type == 1 and dns.qry[0].class == 1
	and	
	// ex., mjffavtomskxfamakshkfhfevk33qb6cz3ko7yxl6ak74fim3amsekae.github.com
	with qry_name = dns.qry[0].name, nlabels = qry_name.labels.total :
	(
		// minimum query name length (worst-case scenario)
		// and number of labels/segments > 2
		string.length(qry_name.qname) > 60 and nlabels > 2
		and
		with first_seg = qry_name.labels.segments[0]:
		(
			string.length(first_seg) == 56
			and
			first_seg matches /^[a-z2-7]{56}$/
		)
	)
}

// this is needed since the actual packet is a mimic of a DNS Query packet
// this rule uses the raw UDP PaID to validate all the indicators
rule icmp_ghost_implant_dns_udp_query_c2_detection
{
    meta:
	
      description = "Detect ICMP-Ghost DNS UDP Query C2 control command traffic"
	  reference   = """https://github.com/JM00NJ/ICMP-Ghost-A-Fileless-x64-Assembly-C2-Agent
					           https://netacoding.com/posts/icmp-ghost/
                     https://blog.netomize.ca/detect-icmp-ghost-implant-icmp-and-dns-tunnelling-c2-traffic-using-packetsmith-yara-x-icmp-detection-modules
	                """	  
      filter      = "Frames (frames:)"
      author      = "Netomize"
      date        = "08/11/2026"
	  		
    strings:
		// flags, questions, answer rrs, authority rrs, additional rrs
		$dheader    = { 01 00 00 01 00 00 00 00 00 00 }
		$qname_rgx  = /[a-z2-7]/
		$type_class = { 00 00 01 00 01 }
	
	condition:
	
		udp.is_set
		and 
		with udata = udp.data.offset, qname = udp.data.offset + 12, usize = udp.data.size :
		(
			// asymmetric authentication
			((uint16be(udata) >> 8) + (uint16be(udata) & 0xff)) == 0xff
			and
			$dheader at (udata + 2)
			and
			// get qname length
			uint8(qname) == 56
			and
			// check subdomain character set
			$qname_rgx in (qname + 1 .. qname + 1 + uint8(qname))
			and
			// check end of label, type and class in reverse
			$type_class at (udata + usize - 5)
		)	
}
