rule Spyware_Library_AppCloner {
    meta:
        author = "CYB3RMX_"
        confidence = "high"
        description = "Rule for detecting libappcloner.so existence"
    strings:
        $lib_magic = { 7F 45 4C 46 02 01 01 00 }
        $app_1 = "AppCloner"
        $app_2 = "com/applisto/appcloner/classes/AppClonerNative"
    condition:
        $lib_magic at 0 and all of ($app_*)
}

rule Spyware_Library_SandHook {
    meta:
        author = "CYB3RMX_"
        confidence = "high"
        description = "Rule for detecting libsandhook.so existence"
    strings:
        $lib_magic = { 7F 45 4C 46 02 01 01 00 }
        $sand_1 = "gHookMode"
        $sand_2 = "hookClassInit"
        $sand_3 = "nativeHookNoBackup"
        $sand_4 = "_ZN8SandHook10InstDecode6decodeEPvmPNS_11InstVisitorE"
        $sand_5 = "_ZN8SandHook21PCRelatedCheckVisitor5visitEPNS_4InstEmm"
        $sand_6 = "hook_native"
        $sand_7 = "com/swift/sandhook/ArtMethodSizeTest"
        $sand_8 = "com/swift/sandhook/SandHookMethodResolver"
        $sand_9 = "SandHooker"
        $sand_10 = "Java_com_swift_sandhook_ClassNeverCall_neverCallNative"
    condition:
        $lib_magic at 0 and any of ($sand_*)
}