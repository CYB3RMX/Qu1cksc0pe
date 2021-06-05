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

rule Mazain_strings: Banker
{
	meta:
		description = "This rule detects Mazain malware based on strings"
		sample = "f4672da546b51b2978e10ff97fbc327665fb2c46ea96cea3e751b33b044b935d"

	strings:
		$required_1 = "activity_inj"
		$required_2 = "activity_go_adm"
		$required_3= "activity_activ_location"
		
		$opt_1 = "$$res/mipmap-xxhdpi-v4/ic_launcher.png"
		$opt_2 = "android.intent.action.NEW_OUTGOING_CALL"
		$opt_3 = "com.example.livemusay.myapplication"
		$opt_4 = "android.intent.action.QUICKBOOT_POWERON"
		$opt_5 = "android.permission.QUICKBOOT_POWERON"
		$opt_6 = "res/layout/activity_inj.xml"
		$opt_7 = "res/layout/activity_go_adm.xml"
		$opt_8 = "res/layout/r_l.xml"
		$opt_9 = "encrypted-storage"
		$opt_10 = "android.app.action.DEVICE_ADMIN_DISABLED"
		

	condition:
		all of ($required_*) and 2 of ($opt_*)
		
		
}