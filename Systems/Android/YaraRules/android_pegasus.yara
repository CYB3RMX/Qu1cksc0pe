import "androguard"
import "file"
import "cuckoo"


rule Pegasus : official
{
	meta:
		description = "This rule detects Pegasus variants"
		sample = "ade8bef0ac29fa363fc9afd958af0074478aef650adeb0318517b48bd996d5d5"
		link_one = "https://info.lookout.com/rs/051-ESQ-475/images/lookout-pegasus-android-technical-analysis.pdf"
		link_two = "https://android-developers.googleblog.com/2017/04/an-investigation-of-chrysaor-malware-on.html"

	strings:
		$string_varone_1 = "/system/csk"
		$string_varone_2 = "SystemJumper"
		$string_varone_3 = "TO_REMOVE:)"
		$string_varone_4 = "copyMySuFileToSystem"
		$string_varone_5 = "shouldSuicide"
		
		$string_vartwo_1 = "NetworkMain"
		$string_vartwo_2 = "network.android/libsgn.so"
		
		$string_varthree_1 = "chmod isSu :"
		$string_varthree_2 = "getApkInfos"
		$string_varthree_3 = "has_phone_number"
		$string_varthree_4 = "pegasus"
		$string_varthree_5 = "systemCall end:"
		



	condition:

	(all of ($string_varone_*) ) or
	(all of ($string_vartwo_*) ) or
	(all of ($string_varthree_*) and $string_varone_1 ) or
	androguard.certificate.sha1("516f8f516cc0fd8db53785a48c0a86554f75c3ba") or 
	androguard.certificate.sha1("44f6d1caa257799e57f0ecaf4e2e216178f4cb3d") or 
	androguard.certificate.sha1("7771af1ad3a3d9c0b4d9b55260bb47c2692722cf") or
	androguard.certificate.sha1("31a8633c2cd67ae965524d0b2192e9f14d04d016")
}