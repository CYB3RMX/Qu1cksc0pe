rule koodous : BTC_ETH
{
	meta:
		description = "This rule detects bitcoin and ethereum"
		
	strings:
		$a = "/^(0x)?[0-9a-fA-F]{40}$/"
		$b = "/^(1|3)[a-zA-Z0-9]{24,33}$/"
		$c = "/^[^0OlI]{25,34}$/"
		
	condition:
		$a or ($b and $c)		
}