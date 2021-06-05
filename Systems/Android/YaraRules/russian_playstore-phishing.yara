rule russianTrojan{
	meta:
		description="This rule detects the russian playstore phising apk"
		sample="c220f4f4e0fbeaf4128c15366819f4e61ef949ebc0bd502f45f75dd10544cc57"
		source="https://koodous.com/apks/c220f4f4e0fbeaf4128c15366819f4e61ef949ebc0bd502f45f75dd10544cc57"

	strings:
		$url="http://www.antivirus-pro.us/downloads/list.txt"
		$url2="www.antivirus-pro.us"
		$url3="antivirus-pro.us"

	condition:
		any of ($url*)
}