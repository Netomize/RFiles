import "math"

/*
    - Packet sample   

	  00000000  64 6d 00 01 00 00 00 8c  7b 22 54 6f 6b 65 6e 22   dm...... {"Token"
	  00000010  3a 22 44 6d 74 70 22 2c  22 4d 65 74 61 64 61 74   :"Dmtp", "Metadat
	  00000020  61 22 3a 7b 22 49 64 22  3a 22 44 42 35 33 45 38   a":{"Id" :"DB53E8
	  00000030  38 45 2d 38 34 44 38 44  34 41 37 22 2c 22 54 79   8E-84D8D 4A7","Ty
	  00000040  70 65 22 3a 22 44 6f 74  6e 65 74 2d 54 63 70 44   pe":"Dot net-TcpD
	  00000050  6d 74 70 22 2c 22 52 6f  6c 65 22 3a 22 43 6c 69   mtp","Ro le":"Cli
	  00000060  65 6e 74 22 7d 2c 22 49  64 22 3a 6e 75 6c 6c 2c   ent"},"I d":null,
	  00000070  22 4d 65 73 73 61 67 65  22 3a 6e 75 6c 6c 2c 22   "Message ":null,"
	  00000080  53 69 67 6e 22 3a 31 33  2c 22 53 74 61 74 75 73   Sign":13 ,"Status
	  00000090  22 3a 30 7d                                        ":0}
	
	[ packet structure ]
	
	  offset     len      description
      ------     ----     -----------
      0x00       0x02 	  magic bytes "dm"
	  0x02       0x02     control command
	  0x04       0x04     data length starting from offset 0x08
		
*/

rule malware_fdmtp_status_request
{
    meta:
	
      description  = "Detect FDMTP status request TCP packet to the server (the malware)"
	  reference    = "https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant"
      filter       = "Frames (frames:)"
	  sha1         = "2cc0425a90a39ac4eedadd59caaafad5b50f8420"
      author       = "Netomize"
      date         = "08/05/2026"

	strings:
	
	  // check for the first char case-insensitive
	  $token    = { 22 (54|74) 6F 6B 65 6E 22 }          // "Token"
	  $metadata = { 22 (4D|6D) 65 74 61 64 61 74 61 22 } // "Metadata"
      $type     = { 22 (54|74) 79 70 65 22 }             // "Type"
      $role     = { 22 (52|72) 6F 6C 65 22 }             // "Role"

    condition:

	  tcp.is_set
	  and
	  flow.to_server
	  and	  
	  with buff = tcp.data.offset, buff_sz = tcp.data.size :
		(
			buff_sz > 74
			and
			uint16be(buff+2) == 0x0001
			and
			uint32be(buff+4) == (buff_sz - 8) // deducing the size of the packet (minus the header)
			and
			// check for the string matches in no particular order
			$token in (8..(buff_sz - 8))
			and
			$metadata in (8..(buff_sz - 8))
			and
			$type in (8..(buff_sz - 8))
			and
			$role in (8..(buff_sz - 8))
		)
}

rule malware_fdmtp_ctrl_cmds_check
{
    meta:
	
      description  = "Detect FDMTP control commands"
	  reference    = "https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant"
      filter       = "Frames (frames:)"
	  sha1         = "2cc0425a90a39ac4eedadd59caaafad5b50f8420"
      author       = "Netomize"
      date         = "08/05/2026"

	  /*
		- Packet sample

		  00000000  64 6d 00 01 00 00 00 8c  7b 22 54 6f 6b 65 6e 22   dm...... {"Token"
		  00000010  .  .  .
	  */

    condition:

	  tcp.is_set
	  and	  
	  with buff = tcp.data.offset, buff_sz = tcp.data.size :
		(		    
			buff_sz > 8 // early exit
			and
			uint16be(buff) == 0x646d // "md" -> magic bytes
			and
			for any ctrl_cmd in (0x01, 0x04, 0x05, 0x0e, 0x0f): (uint16be(buff+2) == ctrl_cmd)
			and
			uint32be(buff+4) == (buff_sz - 8) // deducing the size of the packet (minus the header)
			and
			// each of those control commands carry enough data for the entropy value to be > 4
			math.entropy(buff + 8, buff_sz - 8) > 4
		)
}