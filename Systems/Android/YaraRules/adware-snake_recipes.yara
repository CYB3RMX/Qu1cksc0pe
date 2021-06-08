import "androguard"

rule Adware : SnakeRecipes
{
    meta:
        description = "Possible adware application"
        sample = "0d822b51c086b0c53abcb6504110a641aa9585caaa3287438e10bdc45fe43561"
		
	strings:
		$c1_1 = "matbakhomwalid2017free06" nocase
		$c1_2 = "b1a78415-d04c-4698-b69c-24c3c555649c" nocase
		$c1_3 = "EhUbWAcbLRoGAD5FHQAJ" nocase
		
	condition:
		1 of ($c1_*)
		and (
			androguard.filter(/PACKAGE_REPLACED/) or
			androguard.filter(/PACKAGE_ADDED/)
		)
		and androguard.filter(/ghrataneomwalide06.matbakhomwalid2017free06/)
		and (
			androguard.permission(/ACCESS_NETWORK_STATE/) or 
			androguard.permission(/RECEIVE_BOOT_COMPLETED/)
		)
}