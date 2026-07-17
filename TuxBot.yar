import "math"

rule tuxbot_malware_tcp_checkin_magic_dword
{ 
	meta:
	
	  description = "TCP checkin packet (client->server)"
	  reference   = "https://unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/"
	  filter      = "Frames (frames:)"
	  sha1        = "12c167b69ad8089299fa342bdc22f99bebea7c01"
	  author      = "Netomize"
	  date        = "07/16/2026"
	  flow_state  = "set,magic_bytes,noalert"

	condition:

	  tcp.is_set and ip4.is_set and not ip4.in_ip6 
	  and 
	  tcp.data.size == 4
	  and
	  flow.to_server   // direction
	  and 
	  math.in_range(port.src, 1024, 65535) // ephemeral ports
	  and
	  uint32be(tcp.data.offset) == 0xdeadbe01	  
}

rule tuxbot_malware_tcp_checkin_public_key
{ 
	meta:
	
	  description = "TCP checkin packet public key (client->server)"
	  reference   = "https://unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/"
	  filter      = "Frames (frames:)"
	  sha1        = "12c167b69ad8089299fa342bdc22f99bebea7c01"
	  author      = "Netomize"
	  date        = "07/16/2026"
	  flow_state  = "isset,magic_bytes,alert:unset"

	condition:

	  tcp.is_set and ip4.is_set and not ip4.in_ip6 
	  and 
	  tcp.data.size == 32
	  and
	  flow.to_server   // direction
	  and
	  math.in_range(port.src, 1024, 65535) // ephemeral ports
	  and
	  // random 32 bytes - public key
	  math.entropy(tcp.data.offset, 32) > 4
}
