import "androguard"
rule BankBot2
{
	strings:
		$a0 = "/private/set_data.php"
		$a1 = "/private/settings.php"
		$a2 = "/private/add_log.php"
		$b = "/private/tuk_tuk.php"
		
	condition:
		$b and 1 of ($a*)
}