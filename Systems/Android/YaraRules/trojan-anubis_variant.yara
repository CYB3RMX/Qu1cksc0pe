import "androguard"

rule Anubis_Variant : BankBot
{
	meta:
        description = "Anubis malware targeting banks"
		source = ""
	
	strings:
		$c2_1 = "/o1o/a6.php" nocase
		$c2_2 = "/o1o/a14.php" nocase
		
	condition:
		$c2_1 and $c2_2
		and (
			androguard.permission(/android.permission.RECEIVE_SMS/) 
			or androguard.permission(/android.permission.READ_SMS/)
			or androguard.permission(/android.permission.SEND_SMS/)
		)
}