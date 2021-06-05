import "androguard"
import "file"
import "cuckoo"
import "droidbox"

rule phonecall : fake
{
	meta:
		description = "Phone Caller Programs"

	condition:
		droidbox.phonecall(/./)
		
}