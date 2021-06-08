import "androguard"

rule FakeInst
{
	meta:
        description = "FakeInst evidences"

	strings:
		$1 = "res/raw/mccmnc.txt" wide ascii
		$2 = "Calculated location by MCCMNC" wide ascii
		$3 = "getCost" wide ascii

   	condition:
		all of them
}