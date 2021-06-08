import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Android.Cerberus"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		  $a = "grabbing_google_authenticator2"
        $b = "run_app"
        $c = "change_url_connect"
        $d = "grabbing_pass_gmail"
        $d2 = "change_url_recover"
        $d3 = "send_mailing_sms"
        $d4 = "access_notifications"
        $d5 = "sms_mailing_phonebook"

	condition:
		all of them
		
}