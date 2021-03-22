rule Anti_Reversing_Techniques {
    meta:
      author = "CYB3RMX_"
      confidence = "high"
      description = "This contains strings about Anti-Debugging and Anti-Reversing techniques in Android libraries."
    strings:
      $lib_magic = { 7F 45 4C 46 02 01 01 00 }
      $str_1 = "Java_com_guardsquare_dexguard_runtime_detection_DebugBlocker_c"
      $str_2 = "Java_com_guardsquare_dexguard_runtime_detection_EmulatorDetector_b"
      $str_3 = "Java_com_guardsquare_dexguard_runtime_detection_HookDetector_d"
      $str_4 = "resumeVM"
      $str_5 = "suspendVM"
      $str_6 = "trampolineManager"
    condition:
      $lib_magic at 0 and any of ($str_*)
}