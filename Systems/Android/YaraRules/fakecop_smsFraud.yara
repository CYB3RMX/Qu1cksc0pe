rule Fakecop_SMSFraud_library {
    meta:
      author = "CYB3RMX_"
      confidence = "high"
      description = "This rule contains strings about Fakecop's library."
    strings:
      $lib_magic = { 7F 45 4C 46 02 01 01 00 } // ELF exectuable
      $str_1 = "hackDir"
      $str_2 = "WhatServiceAgent"
      $str_3 = "EmpService"
      $str_4 = "qrga9"
      $str_5 = "BdServiceAgent"
    condition:
      $lib_magic at 0 and any of ($str_*)
}
