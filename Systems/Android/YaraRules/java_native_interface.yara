rule JNI_usage {
    meta:
        author = "CYB3RMX_"
        confidence = "high"
        description = "Rule for detecting JNI usage."
    strings:
        $lib_magic = { 7F 45 4C 46 02 01 01 00 }
        $str_1 = "JNI_OnLoad"
        $str_2 = "_ZN7_JNIEnv11GetMethodIDEP7_jclassPKcS3_"
        $str_3 = "registerNatives"
        $str_4 = "JNI Loaded"
        $str_5 = "JNI_Load_Ex"
    condition:
        $lib_magic at 0 and any of ($str_*)
}

rule JIT_usage {
    meta:
        author = "CYB3RMX_"
        confidence = "high"
        description = "Rule for detecting JIT compiler usage."
    strings:
        $lib_magic = { 7F 45 4C 46 02 01 01 00 }
        $jit_1 = "jitLoad"
        $jit_2 = "jit_lib_path"
        $jit_3 = "jit_compile_method"
        $jit_4 = "jit_load"
        $jit_5 = "globalJitCompileHandlerAddr"
    condition:
        $lib_magic at 0 and all of ($jit_*)
}