import "androguard"


rule hacking_team : stcert
{
	meta:
		description = "This rule detects the apk related to hackingteam - These certificates are presents in mailboxes od hackingteam"
		samples = "c605df5dbb9d9fb1d687d59e4d90eba55b3201f8dd4fa51ec80aa3780d6e3e6e"

	strings:
		$string_a_1 = "280128120000Z0W1"
		$string_a_2 = "E6FFF4C5062FBDC9"
		$string_a_3 = "886FEC93A75D2AC1"
		$string_a_4 = "121120104150Z"
		
		$string_b_1 = "&inbox_timestamp > 0 and is_permanent=1"
		$string_b_2 = "contact_id = ? AND mimetype = ?"
		
		$string_c = "863d9effe70187254d3c5e9c76613a99"
		
		$string_d = "nv-sa1"

	condition:
		(any of ($string_a_*) and any of ($string_b_*) and $string_c and $string_d) or
		androguard.certificate.sha1("B1BC968BD4F49D622AA89A81F2150152A41D829C") or 	  
		androguard.certificate.sha1("3FEC88BA49773680E2A3040483806F56E6E8502E") or 
		androguard.certificate.sha1("C1F04E3A7405D9CFA238259730F096A17FCF2A4F") or 
		androguard.certificate.sha1("6961124AF170D9C0FF2B0571328CB6C71D6FD096") or 
		androguard.certificate.sha1("D198025BF15D7A19488B780E1B9AAD27BBE6C4A9")	or
		androguard.certificate.sha1("24575B8782D44CACB72253FEEB9DF811D0E12C37") or
		androguard.certificate.sha1("4E40663CC29C1FE7A436810C79CAB8F52474133B") or
		androguard.certificate.sha1("638814BFA962060E0869FFF41EDD2131C74B5001") or
		//androguard.certificate.sha1("3EEE4E45B174405D64F877EFC7E5905DCCD73816") or //Framaroot
		androguard.certificate.sha1("E4E57FC7ED86D6F4A8AB2C12C908FBD389C8387B") or
		androguard.certificate.sha1("C4CF31DBEF79393FD2AD617E79C27BFCF19EFBB3") or
		androguard.certificate.sha1("2125821BC97CF4B7591E5C771C06C9C96D24DF8F")
		//6ABB21BC00C8A2E83E6F0C47781BE9880CB6E4F7 this certification could be stolen
		//018E450708B953ABE19B13AB3691D159C90A71B6 this certification could be stolen
		//41227A83A594395A66671F5EDE75F4C794109712 this certification could be stolen

		
}