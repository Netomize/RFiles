rule tplink_tl_wr841n_info_disclosure_vuln_cve_2023_50224_v1
{
    meta:
	
	  description = "CVE-2023-50224"
	  tags        = "apt28, forest blizzard, fancy bear, strontium, sednit, sofacy"
    filter      = "Frames (frames:)"
	  reference   = """https://nvd.nist.gov/vuln/detail/cve-2023-50224
					           https://www.ncsc.gov.uk/news/apt28-exploit-routers-to-enable-dns-hijacking-operations
					           https://www.ic3.gov/PSA/2026/PSA260407
					           https://bestwing.me/tp-link-wr841n-router-cve-analysis.html
					        """
	  author      = "Netomize"
	  date        = "04/21/2026"	
	  		
    strings:

		// GET /loginFs/./dropbear/dropbearpwd HTTP/1.1
		$uri = /GET \/loginFs\/(?:\.|%2[eE])\/dropbear\/dropbearpwd HTTP\/1\.[01]\r?\n/
	
	  condition:

		tcp.is_set
		and 
		flow.to_server   // direction
		and
		port.dst == 80
		and
		$uri at tcp.data.offset
}
