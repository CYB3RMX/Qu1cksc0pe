import "androguard"

rule PayTMActivity
{
	meta:
		description = "All PayTM SDK Apps"	

	condition:
		androguard.activity("com.paytm.pgsdk.PaytmPGActivity")		
		
}