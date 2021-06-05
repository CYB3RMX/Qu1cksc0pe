import "androguard"


rule Sparkasse : Fake Banking App
{
	condition:
		(
		  androguard.app_name("Sparkasse") 
		  or androguard.app_name("Sparkasse+")
		  or androguard.app_name("Sparkasse+ Tablet")
		  or androguard.app_name("Sparkasse Update")
		  or androguard.app_name("Sparkasse Verify")
		  or androguard.app_name("Sparkasse Sicherheitszertifikat")
		  or androguard.app_name("Sparkasse Zertifikat")
		  or androguard.app_name("Sparkasse Sicherheit")
		)
		and not androguard.certificate.sha1("0DADCA40A960FF65BB72104378BE92DB4051B28B")
}


rule Postbank : Fake Banking App
{
	condition:
		(
		  androguard.app_name("Finanzassistent")
		  or androguard.app_name("Postbank")
		  or androguard.app_name("Postbank Finanzassistent")
		  or androguard.app_name("Postbank Sicherheitszertifikat")
		  or androguard.app_name("Postbank Verify")
		  or androguard.app_name("Postbank Update")
		  or androguard.app_name("Postbank Zertifikat")
		  or androguard.app_name("Postbank Sicherheit")
		) 
		and not androguard.certificate.sha1("73839EC3A528910B235859947CC8424543D7B686")
}


rule Volksbank : Fake Banking App
{
	condition:
		(
		   androguard.app_name("VR-Banking")
		   or androguard.app_name("Volksbank")
		   or androguard.app_name("Volksbank Update")
		   or androguard.app_name("Volksbank Verify")
		   or androguard.app_name("Volksbank Sicherheitszertifikat")
		   or androguard.app_name("Volksbank Zertifikat")
		   or androguard.app_name("Volksbank Sicherheit")
		)
		and not androguard.certificate.sha1("ADDB5ED43A27660E41ACB1D39E85DDD7B9C9807C")
}


rule Commerzbank : Fake Banking App
{
	condition:
		(
		   androguard.app_name("Commerzbank")
		   or androguard.app_name("Commerzbank Update")
		   or androguard.app_name("Commerzbank Verify")
		   or androguard.app_name("Commerzbank Sicherheitszertifikat")
		   or androguard.app_name("Commerzbank Zertifikat")
		   or androguard.app_name("Commerzbank Sicherheit")
		)
		and not ( androguard.certificate.sha1("1BA105AB48190B0369A07BA7E9AA2E68952A2DD1") 
			or androguard.certificate.sha1("B7921B2DFC5D6DEB60ED9F6E969CD4D6DBDF2456")
		)
}


rule DKBpushTAN : Fake Banking App
{
	condition:
		(
		  androguard.app_name("DKB-pushTAN")
		  or androguard.app_name("TAN2go")
		  or androguard.app_name("DKBTAN2go")
		) 
		and not androguard.certificate.sha1("B4199718EAA0E676755AF77419FB59ABF7FECE00")
}