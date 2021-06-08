import "androguard"

rule EventBot
{
	meta:
		description = "This rule detects Trojan.AndroidOS.EventBot"
		sampleMD5 = "b0dbbf5df8b1eda3c1044ddd56ec5768"
		source = "https://www.cybereason.com/blog/eventbot-a-new-mobile-banking-trojan-is-born"

	strings:
		$string_1 = "eventBot"
		$string_2 = "onAccessibilityEvent"
		
	condition:
		all of ($string_*) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and
		androguard.permission(/android.permission.READ_SMS/)
}