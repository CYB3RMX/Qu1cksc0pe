import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Appdome"

	strings:
		$ = "APPDOME_INTERNAL_GOOD_FSQUEUE"
		$ = "res/drawable/splash_appdome.png"
		$ = "_appdome_splash"
		$ = "AppdomeInternalAppdomeSSOMessage"
		$ = "AppdomeSecurityAlert"
		$ = "APPDOME_INTERNAL_EXPIRE_ON_POLICY"
		$ = "X-APPDOME-MARKEDr"
		$ = "(AppdomeError)"
		$ = "/efs/libloader_cache_android/"
		$ = "/ANTAMP__EFS__SPLASH__EVENTS__FAKE_JNIONLOAD"

	condition:
		any of them
		
}