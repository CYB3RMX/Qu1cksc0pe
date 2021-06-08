import "androguard"

rule Trojan_Banker_Marcher {
	meta:
	description = "Trojan-Banker targeting Erste Bank Austria, and many others (Marcher)"
		
	strings:

		$ = "17817363627@163.com"
		$ = "SHA1-Digest: 0lCO/Q8bPDm8SyrRcp46Kx+4NPg="
		$ = "SHA1-Digest: MzBgnoodgsYtDvNxEGMil4Ypklk="
		
		$ = "ac-ab.cc"
		$ = "appp-world.at"
		$ = "appppp.at"
		$ = "appsecure57703.cc"
		$ = "appsecure57704.cc"
		$ = "appsecure57705.cc"
		$ = "austriaservices.cc"
		$ = "casserver-login.php"
		$ = "erste-sicherheitszertifkat.eu"
		$ = "erste-sicherheitszertifkat.in"
		$ = "servicesupdaters.com"
		$ = "servicesupdaterss.com"
		$ = "serviceupdates.cc"
		$ = "world-appp.at"
		$ = "xerography.cc"
		$ = "chudresex.at"
		$ = "coxybajau.net"
		$ = "limboswosh.com"
		$ = "memosigla.su"
		$ = "mulsearyl.ru"
		$ = "pishorle.net"
		$ = "sarahtame.at"
		$ = "sarahtame.cc"
		$ = "curlyhair.at"
        $ = "bushyhair.at"
        $ = "pound-sterling-update.at"
		$ = "ldfghvcxsadfgr.at"
		$ = "securitybitches3.at"
		$ = "weituweritoiwetzer.at"
		$ = "securitybitches1.at"
		$ = "securitybitches2.at"
		$ = "wqetwertwertwerxcvbxcv.at"
		$ = "polo777555lolo.at"
		$ = "polo569noso.at"
		$ = "wahamer8lol77j.at"
		$ = "trackgoogle.at"
		$ = "track-google.at"

	condition:
	1 of them and not androguard.package_name(/deebrowser/)

		
}

rule Trojan_Banker_Marcher2 {
	meta:
	description = "Trojan-Banker targeting Erste Bank Austria, and many others (Marcher)"
		
	strings:
		$a = "Name: res/raw/blfs.key"
		$b = "Name: res/raw/config.cfg"


	condition:
	all of them

		
}