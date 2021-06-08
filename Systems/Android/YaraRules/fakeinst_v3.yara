import "androguard"
rule FakeInst_v3
{
	meta:
        description = "FakeInst evidences v3"	
	strings:
		$sa0 = "data.db" wide ascii
		$sa1 = "sms911.ru" wide ascii
		$sb0 = "agree.txt" wide ascii		
		$sb1 = "topfiless.com" wide ascii
   	condition:
		all of ($sa*) or all of ($sb*)
}