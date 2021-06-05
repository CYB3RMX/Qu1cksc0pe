import "androguard"


rule mopub
{
	meta:
		description = "This rule detects aggressive (fake) mopub adware"
		sample = "aad96bdaad938b4ddb6b7ceb11311a99f21a2d4351566efc8ca075b52d9bc6b1"
		author = "https://twitter.com/agucova"

	strings:
		$number = ";njASk3`"
		$wstring = ";38p`_w&"
		$anotherstring = "/7#,v\"<s"
		$evenanother = "q;KAzzz-"

	condition:
		androguard.certificate.sha1("41653FD4CBC306FEF0DD26D68D1AB416285568C8") or
		androguard.package_name("com.mopub") or
		($number and $wstring and $anotherstring and $evenanother)
}