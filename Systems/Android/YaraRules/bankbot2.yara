import "androguard"

rule BankBot
{
	meta:
		sample = "82541c1afcc6fd444d0e8c07c09bd5ca5b13316913dbe80e8a7bd70e8d3ed264"

	strings:
		$ = "/inj/"
		$ = "activity_inj"
		$ = /tuk/
		$ = /cmdlin/

	condition:
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and
		3 of them
		
}