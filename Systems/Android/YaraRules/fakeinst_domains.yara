import "androguard"
rule FakeInst_domains
{
	meta:
        description = "FakeInst evidences domains"		
	strings:
		$1 = "myfilies.net/?u=" wide ascii
		$2 = "m-love12.net/?aid=" wide ascii
		$3 = "androidosoft.ru/engine/download.php?id=" wide ascii
		$4 = "sellapis.ru/am/files/" wide ascii
		$5 = "myapkbox.cu.cc/market.php?t=" wide ascii
		$6 = "wap4mobi.ru/rools.html" wide ascii
		$7 = "filesmob.ru/getfile.php?fl=" wide ascii				
   	condition:
		1 of them
}