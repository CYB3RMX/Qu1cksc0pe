import "androguard"
import "file"

rule chrome_trojan
{
	meta:
		description = "This rule detects the Chrome application and similiar like applications"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	condition:
	    file.md5("c4b7c767287f13be5b244bfc78361e7d") or
		androguard.app_name("Chrome") and
		androguard.permission(/android.permission.CALL_PHONE/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.INTERNET/) and 
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.READ_PROFILE/) and
		androguard.permission(/android.permission.READ_SMS/) and 
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.RECEIVE_MMS/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.WRITE_SMS/) and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and
		androguard.permission(/android.permission.CHANGE_NETWORK_STATE/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/)
		
}