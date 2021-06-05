rule AntiDebugger
{
	strings:
		$a = "/proc/%d/mem"
		$b = "/proc/%d/pagemap"
		$c = "inotify_init"
		$d = "strace"
		$e = "gdb"
		$f = "ltrace"
		$g = "android_server"
		$h = "dvmDbgActive"
		
	condition:
		($a or $b or $c) or ($d and $e and $f) or $g or $h
}