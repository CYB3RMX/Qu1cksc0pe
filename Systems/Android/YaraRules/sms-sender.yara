import "androguard"
rule sms_suspect
{
	meta:
		description = "This rule detects APKs with SMS (write & send) permissions"
	condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.WRITE_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.RECEIVE_SMS/)
}