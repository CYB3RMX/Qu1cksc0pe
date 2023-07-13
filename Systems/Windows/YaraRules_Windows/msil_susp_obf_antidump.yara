import "dotnet"

/* 
Rule to detect script kiddie antidump code, often used by malware
This anti dump code is unstable and only works for 32bit compiled binaries
*/
rule msil_susp_obf_antidump {
    meta:
        author = "dr4k0nia"
        version = "1.0"
        date = "12/03/2023"
        modified = "13/03/2023"
        hash = "ef7bb2464a2b430aa98bd65a1a40b851b57cb909ac0aea3e53729c0ff900fa42"
    strings:
        // Functions required by the antidump
        $import0 = "ZeroMemory"
        $import1 = "VirtualProtect"
        $importt2 = "GetCurrentProcess"

        // Hardcoded offset arrays used by the antidump 
        
        $array0 = {08 00 00 00 0c 00 00 00 10 00 00 00 14 00 00 00
		18 00 00 00 1c 00 00 00 24 00 00 00}
        $array1 = {04 00 00 00 16 00 00 00 18 00 00 00 40 00 00 00
		42 00 00 00 44 00 00 00 46 00 00 00 48 00 00 00
		4a 00 00 00 4c 00 00 00 5c 00 00 00 5e 00 00 00}
        $array2 = 
        {00 00 00 00 08 00 00 00 0c 00 00 00 10 00 00 00
		16 00 00 00 1c 00 00 00 20 00 00 00 28 00 00 00
		2c 00 00 00 34 00 00 00 3c 00 00 00 4c 00 00 00
		50 00 00 00 54 00 00 00 58 00 00 00 60 00 00 00
		64 00 00 00 68 00 00 00 6c 00 00 00 70 00 00 00
		74 00 00 00 04 01 00 00 08 01 00 00 0c 01 00 00
		10 01 00 00 14 01 00 00 1c 01 00 00}
    condition:
        uint16(0) == 0x5a4d
        and dotnet.is_dotnet
        and all of them
}
