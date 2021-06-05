import "androguard"

rule TeleRAT
{
	meta:
		author = "R"
		description = "https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/"
		
	condition:
		androguard.activity(/getlastsms/i) and
		(androguard.service(/botrat/i) or androguard.service(/teleser/i))
}