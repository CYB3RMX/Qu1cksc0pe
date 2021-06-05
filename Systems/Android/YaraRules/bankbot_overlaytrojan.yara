import "androguard"
import "file"
import "cuckoo"


rule Trojan : BankBot
{
	meta:
        description = "Trojan targeting Banks with Overlays"
		source = "https://securify.nl/blog/SFY20170401/banking_malware_in_google_play_targeting_many_new_apps.html"
	
	strings:
		$c2_1 = "/private/tuk_tuk.php" nocase
		$c2_2 = "/private/add_log.php" nocase
		$c2_3 = "/private/set_data.php" nocase
		$c2_4 = "activity_inj" nocase
		
	condition:
		2 of ($c2_*)
		and (
			androguard.permission(/android.permission.RECEIVE_SMS/) 
			or androguard.permission(/android.permission.READ_SMS/)
		)
}


rule Trojan_2 : BankBot
{
	meta:
		sample = "b314e54a1161deccb2f582aaf6356f2e66a2f983dd1c1ebf7a5c5d9f5a873dba"
	
	strings:
		$sms_1 = "Sms Is Deleted !" nocase
		$sms_2 = "SMS is NOT DELETED" nocase
		
		$c2_1 = "/set/log_add.php" nocase
		$c2_2 = "/set/receiver_data.php " nocase
		$c2_3 = "/set/set.php" nocase
		$c2_4 = "/set/tsp_tsp.php" nocase
		
		$cmd_1 = "/proc/%d/cmdline" nocase
		$cmd_2 = "/proc/%d/cgroup" nocase
		
	condition:
		1 of ($sms_*)
		and 2 of ($c2_*)
		and 1 of ($cmd_*)
		and	androguard.permission(/android.permission.RECEIVE_SMS/)
}


rule Trojan_3 : BankBot
{
	meta:
		sample = "ade518199cc4db80222403439ef6c7ee37cd57f820167cf59ee0fcdf5dcd2613"
	
	strings:
		$c2_1 = "settings.php" nocase
		$c2_2 = "set_data.php" nocase
		$c2_3 = "add_log.php" nocase
		$c2_4 = "activity_inj" nocase
		
		$cmd_1 = "/proc/%d/cmdline" nocase
		$cmd_2 = "/proc/%d/cgroup" nocase
		
	condition:
		2 of ($c2_*)
		and 1 of ($cmd_*)
		and (
			androguard.permission(/android.permission.RECEIVE_SMS/) 
			or androguard.permission(/android.permission.READ_SMS/)
		)
}

rule Trojan_4 : BankBot
{
	meta:
		description = "Bankbot - Sample is obfuscated with Allatori // 2017-08-03"
		sample = "787531c2b1bd8051d74ace245e0153938936a0d43137e207e32f7bbc6eb38e1d"

	strings:
		$c_0 = "activity_go_adm"
		$c_1 = "activity_inj"
		$c_2 = "device_admin.xml"

	condition:
		all of ($c_*)
		and (
			androguard.permission(/android.permission.RECEIVE_SMS/) 
			or androguard.permission(/android.permission.READ_SMS/)
		)
}