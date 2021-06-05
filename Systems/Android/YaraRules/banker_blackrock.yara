import "androguard"
import "file"
import "cuckoo"


rule BlackRock : trojan
{
	meta:
		description = "Banker.Android.BlackRock"
		sample = "32d2071ea8b7d815ab3455da2770b01901cef3fc26b9912f725a0a7de2f7d150"

	strings:
        $a1 = "Send_SMS"
        $a2 = "Flood_SMS"
        $a3 = "Download_SMS"

	condition:
		 all of them
		
}