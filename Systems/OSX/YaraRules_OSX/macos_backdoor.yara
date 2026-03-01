rule macOS_ReverseShell_Indicators
{
    meta:
        description = "Detects reverse shell / C2 beacon indicators in Mach-O"
        author      = "Qu1cksc0pe"
        category    = "Backdoor"
    strings:
        $r1 = "/dev/tcp/" ascii wide
        $r2 = "bash -i" ascii wide
        $r3 = "mkfifo" ascii wide
        $r4 = "exec 5<>" ascii wide
        $r5 = "0>&1" ascii wide
        $r6 = "nc -e" ascii wide
        $r7 = "ncat -e" ascii wide
        $r8 = "python -c 'import socket" ascii wide
        $r9 = "perl -e 'use Socket" ascii wide
    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xFEEDFACE or uint32(0) == 0xCAFEBABE)
        and 2 of them
}

rule macOS_ScreenCapture_Spyware
{
    meta:
        description = "Detects screen capture and keylogging capabilities"
        author      = "Qu1cksc0pe"
        category    = "Spyware"
    strings:
        $sc1 = "CGWindowListCreateImage" ascii wide
        $sc2 = "CGDisplayCreateImage" ascii wide
        $sc3 = "CGEventTapCreate" ascii wide
        $sc4 = "IOHIDManagerCreate" ascii wide
        $sc5 = "AVCaptureScreenInput" ascii wide
        $sc6 = "NSEvent addGlobalMonitorForEventsMatchingMask" ascii wide
        $sc7 = "AXIsProcessTrusted" ascii wide
        $sc8 = "SCStreamCreate" ascii wide
    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xFEEDFACE or uint32(0) == 0xCAFEBABE)
        and 2 of them
}

rule macOS_AntiDebug
{
    meta:
        description = "Detects anti-debugging techniques in Mach-O binaries"
        author      = "Qu1cksc0pe"
        category    = "Anti-Analysis"
    strings:
        $a1 = "PT_DENY_ATTACH" ascii wide
        $a2 = "ptrace" ascii wide
        $a3 = "P_TRACED" ascii wide
        $a4 = "csops" ascii wide
        $a5 = "task_get_exception_ports" ascii wide
        $a6 = "mach_vm_region" ascii wide
        $a7 = "SecStaticCodeCheckValidity" ascii wide
        $a8 = "sandbox_check" ascii wide
    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xFEEDFACE or uint32(0) == 0xCAFEBABE)
        and 2 of them
}

rule macOS_Keychain_Stealer
{
    meta:
        description = "Detects keychain credential harvesting"
        author      = "Qu1cksc0pe"
        category    = "Credential Access"
    strings:
        $k1 = "SecKeychainFindGenericPassword" ascii wide
        $k2 = "SecKeychainFindInternetPassword" ascii wide
        $k3 = "SecItemCopyMatching" ascii wide
        $k4 = "kSecClassGenericPassword" ascii wide
        $k5 = "kSecReturnData" ascii wide
        $k6 = "SecKeychainItemCopyAttributesAndData" ascii wide
    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xFEEDFACE or uint32(0) == 0xCAFEBABE)
        and 3 of them
}
