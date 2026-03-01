rule macOS_Dylib_Injection
{
    meta:
        description = "Detects dylib injection / hooking framework indicators"
        author      = "Qu1cksc0pe"
        category    = "Code Injection"
    strings:
        $s1 = "MobileSubstrate" ascii wide
        $s2 = "CydiaSubstrate" ascii wide
        $s3 = "TweakInject" ascii wide
        $s4 = "pspawn_payload" ascii wide
        $s5 = "libhooker" ascii wide
        $s6 = "DYLD_INSERT_LIBRARIES" ascii wide
        $s7 = "SSLKillSwitch" ascii wide
        $s8 = "FridaGadget" ascii wide
        $s9 = "frida-gadget" ascii wide
        $s10 = "cycript" ascii wide
        $s11 = "MSHookFunction" ascii wide
        $s12 = "MSHookMessageEx" ascii wide
        $s13 = "fishhook" ascii wide
        $s14 = "dyld_stub_binder" ascii
        $s15 = "task_for_pid" ascii wide
    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xFEEDFACE or uint32(0) == 0xCAFEBABE)
        and 2 of them
}

rule macOS_DYLD_Environment_Abuse
{
    meta:
        description = "Detects DYLD environment variable abuse for injection"
        author      = "Qu1cksc0pe"
        category    = "Code Injection"
    strings:
        $d1 = "DYLD_INSERT_LIBRARIES" ascii wide
        $d2 = "DYLD_LIBRARY_PATH" ascii wide
        $d3 = "DYLD_FRAMEWORK_PATH" ascii wide
        $d4 = "DYLD_FORCE_FLAT_NAMESPACE" ascii wide
    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xFEEDFACE or uint32(0) == 0xCAFEBABE)
        and 2 of them
}
