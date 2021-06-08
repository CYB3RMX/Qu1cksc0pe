import "androguard"
import "cuckoo"
import "droidbox"


rule anubis
{
	meta:
		description = "Trojan-Banker.AndroidOS.Anubis"
		
	condition:
		droidbox.written.data(/spamSMS/i) and
		droidbox.written.data(/indexSMSSPAM/i) and
		droidbox.written.data(/RequestINJ/i) and
		droidbox.written.data(/VNC_Start_NEW/i) and
		droidbox.written.data(/keylogger/i) 
		
}