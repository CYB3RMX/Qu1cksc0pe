import "androguard"
rule FakeInst_v2
{
	meta:
        description = "FakeInst evidences v2"	
	strings:
		$1 = "loadSmsCountabc123" wide ascii
		$2 = "loadSmsCountMethod" wide ascii
		$3 = "sentSms" wide ascii
		$4 = "getSentSms" wide ascii
		$5 = "maxSms" wide ascii
   	condition:
		all of them
}