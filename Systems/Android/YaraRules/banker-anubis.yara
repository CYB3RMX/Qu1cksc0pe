import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		sample = "e85cba233a555a2ecb0956c6b6fa040ad12fd9cb496fcff3d3b3a80dfe6758dc"

	strings:
       $a1 = "U2VuZF9HT19TTVM="
       $a2 = "QUxMU0VUVElOR1NHTw=="
       $b1 = "Send_GO_SMS"
       $b2 = "del_sws"

	condition:
		all of ($a*) or all of ($b*)
		
}