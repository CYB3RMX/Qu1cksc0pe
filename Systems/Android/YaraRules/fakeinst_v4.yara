import "androguard"
rule FakeInst_v4
{
	meta:
        description = "FakeInst evidences v4"	
	strings:
		$1 = "android/telephony/gsm/SmsManager" wide ascii
		$2 = "getText123" wide ascii
		$3 = "setText123" wide ascii
		$4 = "text123" wide ascii
   	condition:
		all of them
}