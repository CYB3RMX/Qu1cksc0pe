import "androguard"

rule Adwo:adware
{
	condition:
		androguard.certificate.sha1("ce147adf1b178d6a7f521829d0a30e5a7198cf24")
		or androguard.certificate.sha1("6e72c81f13447b99653c8bdd37864d349d9e429a")
}

rule CapAdwo:Adware
{
	condition:
		androguard.certificate.sha1("CE147ADF1B178D6A7F521829D0A30E5A7198CF24")
		or androguard.certificate.sha1("6E72C81F13447B99653C8BDD37864D349D9E429A")
}