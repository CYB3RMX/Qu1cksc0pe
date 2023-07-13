import "dotnet"

rule msil_susp_obf_xorstringsnet {
    meta:
        description = "Detects XorStringsNET string encryption, and other obfuscators derived from it"
        author = "dr4k0nia"
        version = "1.0"
        date = "26/03/2023"
    strings:
        $pattern = { 06 1E 58 07 8E 69 FE17 }
    condition:
        uint16(0) == 0x5a4d
        and filesize < 25MB
        and dotnet.is_dotnet
        and $pattern
}
