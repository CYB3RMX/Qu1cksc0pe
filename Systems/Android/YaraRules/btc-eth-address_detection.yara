rule koodous : BTC_ETH_addr_detection
{
	meta:
		description = "This rule detects bitcoin and ethereum addresses"
		
	strings:
		$a = "/^(0x)?[0-9a-fA-F]{40}$/"
		$b = "/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$/"
		
	condition:
		$a or $b		
}