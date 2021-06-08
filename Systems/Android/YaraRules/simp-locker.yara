import "androguard"
import "file"
import "cuckoo"


rule SimpLocker
{
	meta:
		description = "This rule aims to detect SimpLocker and other related ransomware"
	

	strings:
		$a = "simplelocker"

	condition:
		$a or
		androguard.app_name("Sex xionix") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/)
		
}