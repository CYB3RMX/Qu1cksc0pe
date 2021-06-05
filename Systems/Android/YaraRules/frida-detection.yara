import "androguard"
import "file"
import "cuckoo"


rule frida : anti_hooks
{

	strings:
		$a = "frida-gum"
		$b = "frida-helper"
		$c = "re.frida.HostSession10"
		$d = "AUTH ANONYMOUS 474442757320302e31\\r\\n"
		$e = "re.frida"

		$f = "00 4C 49 42 46 52 49 44 41 5F 41 47 45  4E 54 5F 31 2E 30 00" // "LIBFRIDA_AGENT_1.0"
		$g = "00 66 72 69 64 61 5F 61 67 65 6E 74 5F 6D 61 69 6E 00" // "frida_agent_main"
		$h = "00 66 72 69 64 61 00" // "frida"
	condition:
		any of them
}