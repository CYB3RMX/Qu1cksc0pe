rule shellcode
{
    meta:
        author = "nex"
        description = "Matched shellcode byte patterns"
        modified = "Glenn Edwards (@hiddenillusion)"
    strings:
        $s0 = { 64 8b 64 }
        $s1 = { 64 a1 30 }
        $s2 = { 64 8b 15 30 }
        $s3 = { 64 8b 35 30 }
        $s4 = { 55 8b ec 83 c4 }
        $s5 = { 55 8b ec 81 ec }
        $s6 = { 55 8b ec e8 }
        $s7 = { 55 8b ec e9 }
    condition:
        for any of ($s*) : ($ at entrypoint)	
}