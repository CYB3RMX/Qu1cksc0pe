rule ransomware
{
	meta:
		description = "This rule detects Ransomware"
		sample = "185c5b74d215b56ba61b4cebd748aec86e478c6ac06aba96d98eff58b24ee824"
		source = "https://twitter.com/LukasStefanko/status/683997678821322752"

	strings:
		$a = "findFrontFacingCamera"
		$c = "runReceiver"
		$d = "onCarete"
		
	condition:
		all of them
		
}