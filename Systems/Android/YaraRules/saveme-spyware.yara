import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "SaveMe, SMS and CALL spyware"
		sample = "919a015245f045a8da7652cefac26e71808b22635c6f3217fd1f0debd61d4330"

	strings:
		$a = {68 74 74 70 3a 2f 2f 74 6f 70 65 6d 61 72 6b 65 74 69 6e 67 2e 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 67             6f 6f 67 6c 65 66 69 6e 61 6c 2f 64 61 74 61 2e 70 68 70}

	condition:
		androguard.package_name("com.savemebeta") and
		androguard.app_name("SaveMeBeta.apk") and
		androguard.activity(/com.savemebeta.SplashScreen/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.BLUETOOTH/) and
		androguard.permission(/android.permission.BLUETOOTH_ADMIN/) and 
		androguard.permission(/android.permission.CALL_PHONE/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and 
		androguard.permission(/android.permission.GET_TASKS/) and
		androguard.permission(/android.permission.READ_CALL_LOG/) and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.WRITE_CALL_LOG/) and
		androguard.permission(/android.permission.WRITE_CONTACTS/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.WRITE_SMS/) and
		androguard.certificate.sha1("b64b84a69a4fe82009e97ac85fa38d4e073f330f") and
		not file.md5("78835947cca21ba42110a4f206a7a486") and 
		$a and
		cuckoo.network.dns_lookup(/topemarketing.com/) 
		
}