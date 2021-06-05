import "androguard"
import "file"
import "cuckoo"


rule virbox : packer
{
	meta:
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "Virbox Protector"

	condition:
		all of them
		
}