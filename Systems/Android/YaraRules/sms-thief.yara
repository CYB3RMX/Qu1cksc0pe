import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects suspicous behaviour from a Hacking app"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
        $text_string = "http://a270915.mcdir.ru/private/add_log.php"

	condition:
		androguard.package_name("anu_bispro.app") and
		androguard.app_name("HackApp") and
		androguard.activity(/com.google.android.gms.people.service.bg.PeopleBackgroundTasks (com.google.android.gms)/i) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.certificate.sha1("27051f1b40be966a6457f08631269fec7b5b737d") and
		not file.md5("c65fa96a4b9e581ca351356f0bccd1b5") and 
		$text_string and
		cuckoo.network.dns_lookup(/a270915.mcdir.ru/)
		
}