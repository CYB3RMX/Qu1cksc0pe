import "androguard"
rule spynote_variants
{
	meta:
		description = "Yara rule for detection of different Spynote Variants"
		source = " http://researchcenter.paloaltonetworks.com/2016/07/unit42-spynote-android-trojan-builder-leaked/"
		author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "SERVER_IP" nocase
		$str_2 = "SERVER_NAME" nocase
		$str_3 = "content://sms/inbox"
		$str_4 = "screamHacker" 
		$str_5 = "screamon"
	condition:
		androguard.package_name("dell.scream.application") or 
		androguard.package_name("com.spynote.software.stubspynote") or
		androguard.certificate.sha1("219D542F901D8DB85C729B0F7AE32410096077CB") or
		all of ($str_*)
}


