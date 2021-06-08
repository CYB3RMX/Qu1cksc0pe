import "androguard"
rule Spywaller
{
	meta:
		description = "Android.Spywaller"
		sample = "7b31656b9722f288339cb2416557241cfdf69298a749e49f07f912aeb1e5931b"
		credits = "http://www.symantec.com/connect/blogs/spyware-androidspywaller-uses-legitimate-firewall-thwart-security-software"
		credits_2 = "http://www.symantec.com/security_response/writeup.jsp?docid=2015-121807-0203-99&tabid=2"
	
	strings:
		$a = "com.qihoo360.mobilesafe" //Malware looks for this app to remove it from device
		$b = "com.lbe.security"
		$c = "cn.opda.a.phonoalbumshou"
		$d = "safety_app"
		
	condition:
		all of them
		and androguard.permission(/android.permission.RESTART_PACKAGES/)
}