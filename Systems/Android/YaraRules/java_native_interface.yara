rule JNI_usage {

    meta:
        author = "CYB3RMX_"
        confidence = "high"
        description = "Rule for detecting JNI."

    strings:
        $lib_magic = { 7F 45 4C 46 02 01 01 00 }
        $str_1 = "JNI_OnLoad"

    condition:
        $lib_magic at 0 and any of ($str_*)
}