import "androguard"
rule : BankBot
{
	meta:
		description = "This rule detects the bankbot app based on various info"
		sample="a607a9903b0101bb1ed87381a6f339f83e721555e9355f889798e7b0df28d3cb"
		sample="f61e3e022cafe04add649eab9173317440845bdbc022060225f3c6d4b2e9d4a1"
		sample="d32d98751178ce0a307254a989d1d26c5601abc1b4ea092b1cb5dd470b48bb32"
		sample="f967498ad1623f631356f5a3de2e958cd2794c653218fb8d1828b4be43069e2e"
		sample="4debd811501958491a44f75d1c116d5ac4276bd1f88d22f81e33fcfff4af2c64"
		sample="537e0e9d762ab89f6607ed31fd407142909c652958f4522bf8b1a9958b3c10de"
		sample="3035dde4fa98cba19591808a6f0c2e64f062cb0210350592b72e7a1d8d27710f"
		sample="a558d2d3e786f9ad00c6329056b84ac007578e422e47b56c7f4a6028abbedbdf"
		sample="a3f8e8dc01b620f5ef1da9faa57bf691247f4c9e153b764ec1296f94403c2caa"
		sample="37292ab423ef462b4df34e84116f85f1d0fcf8f8095045170c332cd7164fdda3"
		sample="b42722eb3be50b74d025055165fc0fa84020df11449062dab2f64621965cb776"
		sample="929d57342c0e97eb225a95e18c6f3045862ae54948528d22b93954876b92dd3a"
	strings:
		$a = "http://5.45.73.20/api/?id=1" nocase
		$c2_1 = "/private/tuk_tuk.php" nocase
		$c2_2 = "/private/add_log.php" nocase
		$c2_3 = "/private/set_data.php" nocase
		$c2_4 = "activity_inj" nocase
	condition:
		2 of ($c2_*) or
		$a and androguard.permission(/android.permission.CALL_PHONE/) 
		or androguard.permission(/android.permission.READ_CONTACTS/)
		or androguard.permission(/android.permission.READ_PHONE_STATE/)		
}