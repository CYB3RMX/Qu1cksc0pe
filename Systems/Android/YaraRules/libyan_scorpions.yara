import "androguard"
import "cuckoo"


rule libyan_scorpions
{
	meta:
		source = "https://cyberkov.com/wp-content/uploads/2016/09/Hunting-Libyan-Scorpions-EN.pdf"
		sample = "e66d795d0c832ad16381d433a13a2cb57ab097d90e9c73a1178a95132b1c0f70"
		dropped = "4e656834a93ce9c3df40fe9a3ee1efcccc728e7ea997dc2526b216b8fd21cbf6"

	strings:
		$ip_1 = "41.208.110.46" ascii wide
		$domain_1 = "winmeif.myq-see.com" ascii wide nocase
		$domain_2 = "wininit.myq-see.com" ascii wide nocase
		$domain_3 = "samsung.ddns.me" ascii wide nocase
		$domain_4 = "collge.myq-see.com" ascii wide nocase
		$domain_5 = "sara2011.no-ip.biz" ascii wide nocase

	condition:
		androguard.url(/41\.208\.110\.46/) or cuckoo.network.http_request(/41\.208\.110\.46/) or
		androguard.url(/winmeif.myq-see.com/i) or cuckoo.network.dns_lookup(/winmeif.myq-see.com/i) or
		androguard.url(/wininit.myq-see.com/i) or cuckoo.network.dns_lookup(/wininit.myq-see.com/i) or
		androguard.url(/samsung.ddns.me/i) or cuckoo.network.dns_lookup(/samsung.ddns.me/i) or
		androguard.url(/collge.myq-see.com/i) or cuckoo.network.dns_lookup(/collge.myq-see.com/i) or
		androguard.url(/sara2011.no-ip.biz/i) or cuckoo.network.dns_lookup(/sara2011.no-ip.biz/i) or
		any of ($domain_*) or any of ($ip_*) or
		androguard.certificate.sha1("DFFDD3C42FA06BCEA9D65B8A2E980851383BD1E3")
		
}