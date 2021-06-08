import "androguard"
rule Mazain: Banker
{
	meta:
		description = "This rule detects Mazain banker"
		sample = "9f3965042c5521ce1eba68f417e9be91cb0050cd8ed5f054a7ad60afc8a4e111"
		author = "A.Sanchez <asanchez@koodous.com>"
	strings:
		$ = "goo.gl/fDqpmZ"
		$ = "22222.mcdir.ru"
		$ = "111111111.mcdir.ru"
		$ = "a193698.mcdir.ru"
		$ = "firta.myjino.ru"
		$ = "ranito.myjino.ru"
		$ = "kinoprofi.hhos.ru"
		$ = "cclen25sm.mcdir.ru"
		$ = "321123.mcdir.ru"
		$ = "000001.mcdir.ru"
		$ = "104.238.176.73"
		$ = "probaand.mcdir.ru"
		$ = "jekobtrast1t.ru"
		$ = "dronnproto.temp.swtest.ru"
		$ = "videoboxonline.com"
		$ = "onlinevtvideos.com"
		$ = "clen1.mcdir.ru"
		$ = "xowarm.ru"
		$ = "foxmix.mcdir.ru"
		$ = "130.0.233.109"
		$ = "spankedteens.pw"
		$ = "46.183.216.173"
		$ = "srv114389.hoster-test.ru"
	condition:
		1 of them
		or androguard.package_name("com.example.livemusay.myapplication")
		or androguard.package_name("kris.myapplication")
		or androguard.package_name("com.bagirase.livemusay.hrre")		
}