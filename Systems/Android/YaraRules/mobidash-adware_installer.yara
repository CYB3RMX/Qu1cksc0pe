import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "MobiDash which installs malicious adware"
		sample = "b41d8296242c6395eee9e5aa7b2c626a208a7acce979bc37f6cb7ec5e777665a"

	strings:
		$a = {68 74 74 70 3a 2f 2f 70 6c 61 79 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 6d 61 72 
			  6b 65 74 70 6c 61 63 65 2f 61 70 70 73 2f 64 65 74 61 69 6c 73 3f 69 64 3d 
			  25 73}

	condition:
		androguard.package_name("com.cardgame.durak") and
		androguard.app_name("Durak.apk") and
		androguard.activity(/com.cardgame.durak.activities.ActivityStart/i) and
		androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.GET_TASKS/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/com.cardgame.durak.permission.C2D_MESSAGE/) and
		androguard.certificate.sha1("8ef70a49ef90432c9cb0248f574b3f48f54df5dc") and
		not file.md5("9e81bf61c5cae2c2856e4103353594fb") and 
		$a and
		cuckoo.network.dns_lookup(/r.tapit.com/) //
}