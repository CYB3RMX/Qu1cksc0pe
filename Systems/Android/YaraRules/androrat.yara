import "androguard"
rule AndroRAT

{
	meta:
		description = "AndroRAT"

	strings:
		$a = "Lmy/app/client/ProcessCommand" wide ascii
		$b = "AndroratActivity" wide ascii
		$c = "smsKeyWord" wide ascii
		$d = "numSMS" wide ascii

	condition:
		$a and ($b or $c or $d)
}