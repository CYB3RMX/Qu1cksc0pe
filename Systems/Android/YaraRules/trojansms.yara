rule trojanSMS
{
	meta:
		description = "This rule detects trojan SMS"
		sample = "ff8ccead81eca2154cf9e891e15f52c8a154ea3aba5e62498b11fb843135837f"
		source = "http://pastebin.com/rLPux7ts"

	strings:
		$a = "sendMultipartTextMessage"
		$b = "l68g66qypPs="
		$c = "MY7WPp+JQGc="
		$d = "com.android.install"
		
	condition:
		all of them
		
}