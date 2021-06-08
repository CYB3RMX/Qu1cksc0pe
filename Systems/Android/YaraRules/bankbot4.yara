import "androguard"

rule BankBot3
{
	strings:
		$ = "chins.php"
		$ = "live.php"
		$ = "add.php"
	condition:
		all of them
}