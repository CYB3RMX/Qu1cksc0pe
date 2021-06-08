rule packers : bangcle
{
	meta:
		description = "This rule detects packers based on files used by them"
		

	strings:
		$bangcle_1 = "libsecmain.so"
		$bangcle_2 = "libsecexe.so"
		$bangcle_3 = "bangcleplugin"
		

	condition:
		all of them
		
}