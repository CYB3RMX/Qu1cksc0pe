rule RedAlert2 : Banker
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$exec_0 = "/system/bin/toolbox ps -p - P -x -c"

		$str_10_0 = "LAUNCH_APP"
		$str_10_1 = "launchApp"

		$str_12_0 = "SEND_USSD"
		$str_12_1 = "sendUssd"

		$res_0 = "146.0.72.85:7878"
		$res_1 = "146.0.72.85"
		$res_2 = "url_dcsiv4t"
		$res_3 = "url_dhfcyseu437"
		$res_4 = "twitter response is NOT OK!"
		$res_5 = "tweet-text"

		$str_5_0 = "RESET_DEFAULT_SMS"
		$str_5_1 = "resetDefaultSms"

		$str_4_0 = "SET_DEFAULT_SMS"
		$str_4_1 = "setDefaultSms"

		$str_7_0 = "GET_CALL_LIST"
		$str_7_1 = "getCallList"

		$str_6_0 = "GET_SMS_LIST"
		$str_6_1 = "getSmsList"

		$str_1_0 = "START_SMS_INTERCEPTION"
		$str_1_1 = "startSmsInterception"

		$str_3_0 = "SEND_SMS"
		$str_3_1 = "sendSms"

		$str_2_0 = "STOP_SMS_INTERCEPTION"
		$str_2_1 = "stopSmsInterception"

		$str_9_0 = "SET_ADMIN"
		$str_9_1 = "setAdmin"

		$str_8_0 = "GET_CONTACT_LIST"
		$str_8_1 = "getContactList"

	condition:
		any of ($res_*) or
		all of ($exec_*) or
		all of ($str_10_*) or
		all of ($str_12_*) or
		all of ($str_5_*) or
		all of ($str_4_*) or
		all of ($str_7_*) or
		all of ($str_6_*) or
		all of ($str_1_*) or
		all of ($str_3_*) or
		all of ($str_2_*) or
		all of ($str_9_*) or
		all of ($str_8_*)
}