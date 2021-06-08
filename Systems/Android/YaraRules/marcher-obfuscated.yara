import "androguard"
import "file"
import "cuckoo"
rule Marcher : more obfuscated versions
{
	meta:
		description = "This rule detects more obfuscated versions of marcher"
		sample = "e5ee5285b004faf53fca9b7c5e2c74316275413ef92f3bcd3a457c9b81a1c13e"
	strings:
		$string_1 = "gp_dialog_password" nocase
		$string_2 = "Visa password" nocase
		$string_3 = "Amex SafeKey password" nocase
		$string_4 = "Secure Code Password" nocase
	condition:
		2 of ($string_*)
		and androguard.permission(/android.permission.RECEIVE_SMS/)
		and androguard.permission(/android.permission.GET_TASKS/)
		and androguard.filter(/.*DEVICE_ADMIN_ENABLED.*/)
}