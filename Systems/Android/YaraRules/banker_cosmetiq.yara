import "androguard"

rule Banker : Cosmetiq 
{
	strings:
		$c2_prefix = "{\"to\":"
		$c2_mid = "\",\"body\":"
		$c2_suffix = "php\"},"
		
		$com1 = "upload_sms"
		$com2 = "send_sms"
		$com3 = "default_sms"
		$com4 = "sms_hook"
		$com5 = "gp_dialog_password"
		$com6 = "gp_password_visa"
		$com7 = "gp_password_master"

	condition:
		all of ($c2_*)
		and 2 of ($com*) 
		and androguard.permission(/android.permission.RECEIVE_SMS/)
		and androguard.permission(/android.permission.GET_TASKS/)
		and androguard.permission(/android.permission.READ_SMS/)
}

rule Banker2 : Cosmetiq by Name
{
	condition:
		androguard.package_name("cosmetiq.fl")
}