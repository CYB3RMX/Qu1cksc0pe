import "androguard"
import "file"
import "cuckoo"


rule VikingBotnet
{
	meta:
		description = "Rule to detect Viking Order Botnet."
		sample = "85e6d5b3569e5b22a16245215a2f31df1ea3a1eb4d53b4c286a6ad2a46517b0c"

	strings:
		$a = "cv7obBkPVC2pvJmWSfHzXh"
		$b = "http://joyappstech.biz:11111/knock/"
		$c = "I HATE TESTERS onGlobalLayout"
		$d = "http://144.76.70.213:7777/ecspectapatronum/"
		$e = "http://176.9.138.114:7777/ecspectapatronum/"
		$f = "http://telbux.pw:11111/knock/"
		
	condition:
		($a and $c) or ($b or $d or $e or $f) 
}