import "androguard"

rule Android_Anubis_v3
{
	meta:
		author = "Jacob Soo Lead Re"
		description = "Anubis newer version."

	condition:
		(androguard.filter(/android.intent.action.DREAMING_STOPPED/i) 
		and androguard.filter(/android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE/i) 
		and androguard.filter(/android.intent.action.USER_PRESENT/i))
}