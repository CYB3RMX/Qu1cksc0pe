import "androguard"
import "file"
import "cuckoo"


rule Trojan : trojans_ttp
{
	meta:
        description = "trojans bankers com overlay e/ou acessibilidade"
		author = "Ialle Teixeira"
	
	strings:
		$c2_1 = "canairizinha" nocase
		$c2_2 = "conexao_BR" nocase
		$c2_3 = "progertormidia" nocase
		$c2_4 = "$controladores_BR" nocase
		$c2_5 = "Anywhere Software" nocase
		$c2_6 = "starter_BR" nocase
		$c2_7 = "b0z" nocase
		$c2_8 = "bolsonaro" nocase
		
	condition:
      androguard.package_name("com.itau") and 2 of ($c2_*)
}