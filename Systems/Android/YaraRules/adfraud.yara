import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta: 
		description = "This rule detects AD fraud"

	condition:
		androguard.url("app/ConfServlet?conf=") or androguard.url("http://ip-api.com/json/?fields=country,countryCode")
		
}