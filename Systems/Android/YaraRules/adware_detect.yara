rule Adware : test
{
	meta:
		description = "Adware Detect"
		sample = "631a898d184e5720edd5f36e6911a5416aa5b4dbbbea78838df302cffb7d36a1"
		author = "xophidia"
	strings:
	
		$string_1 = "21-11734"
		$string_2 = "()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"
		$string_3 = "()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"
		$string_4 = "www.meitu.com"
		$string_5 = "cookiemanager-"

	condition:
		3 of ($*)
}