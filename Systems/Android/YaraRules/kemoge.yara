import "androguard"

rule Kemoge : official
{
	meta:
		description = "This rule detects Kemoge aggresive Adware"
		sample = "0E012F69D493B7CC38FCAFCF495E0BD1290CA94B1AD043FCF255DF3AD5789834"

	strings:
		$a = {20 2D 20 57 72 6F 6E 67 20 50 61 73 73 77 6F 72 64 3F}
		$b = {23 23 23 20 4D 79 53 65 72 76 69 63 65 20 62 65 67 69 6E}
		$c = {34 37 41 46 31 41 31 44 44 36 33 35 35 41 39}
		$d = {42 61 73 65 4C 69 62}
		$e = {63 61 6E 6F 74}
		$f = {72 6F 6F 74 20 61 6C 72 65 61 64 79 20 64 6F 6E 65}


	condition:

		$a and $b and $c and $d and $e and $f

		
}
rule Kemoge_2 : official
{
	meta:
		description = "This rule detects Kemoge aggresive Adware"
		sample = "_"

	strings:
		$a = {6C 61 73 74 53 65 6E 64 49 6E 73 74 61 6C 6C 65 64 50 61 63 6B 61 67 65 49 6E 66 6F 54 69 6D 65 3A}
		$b = {68 6F 75 72 41 66 74 65 72 4C 61 73 74 53 65 6E 64 3A}
		$c = {67 65 74 49 6E 73 74 61 6C 6C 65 64 50 61 63 6B 61 67 65 73 2E 6A 73 70}
		$d = {6B 65 6D 6F 67 65 2E 6E 65 74}


	condition:

		$a and $b and $c and $d

		
}