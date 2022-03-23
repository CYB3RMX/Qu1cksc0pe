rule Win32_Trojan_TrickBot : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "TRICKBOT"
        description         = "Yara rule that detects TrickBot trojan."

        tc_detection_type   = "Trojan"
        tc_detection_name   = "TrickBot"
        tc_detection_factor = 5

    strings:

        $entry_setup = {
            58 (68 | 8B) [6-8] 59 [1-3] E2 ?? 57 8B (C7 | EC) 8B (C7 | EC) 05 ?? ?? ?? ?? 68 [4-5] 
            89 45 [1-2] 8B D7 [3-4] 8B C1 66 AD 85 C0 74 ?? 3B (C1 | C8) (72 | 77) ?? 2B C1 (C1 | D1) 
            [2-4] 8B CF 03 C8 81 C1 ?? ?? ?? ?? 8B 01 59 03 D0 52 EB ?? 89 45 ?? 8B C5 B9 ?? ?? 
            ?? ?? C1 E1 ?? 2B C1 8B 00 89 45 ?? 6A ?? 8B D0 59 FF D2 89 68 ?? 6A ?? 8B D0 FF D2 
        }

        $decrypt_function_snippet = {
            58 8B C8 75 ?? 58 2B F0 50 8B D8 49 75 ?? 59 58 59 5E 5F 5B C3 
        }

        $decrypt_function_snippet_wrapper = {
            55 BD ?? ?? ?? ?? 50 51 52 6A ?? FF 45 ?? 8B 45 ?? 59 F7 E1 8D 8D ?? ?? ?? ?? 03 C8 
            89 4D ?? 8F 41 ?? 8F 41 ?? 8F 41 ?? 8F 41 ?? 8F 01 89 79 ?? 89 71 ?? 8B D1 59 89 4A 
            ?? 55 2B C0 8B C8 8B 02 8B F8 58 41 41 41 41 50 2B C1 8B 00 3B C7 72 ?? 58 C1 E9 ?? 
            49 89 4A ?? E3 ?? FF 55 ?? 8B 55 ?? 8B 4A ?? FF 55 ?? 50 51 50 6A ?? 59 FF 55 ?? FF 
            D0 
        }

    condition:
        uint16(0) == 0x5A4D and
        $entry_setup and
        (
            $decrypt_function_snippet or
            $decrypt_function_snippet_wrapper
        )
}