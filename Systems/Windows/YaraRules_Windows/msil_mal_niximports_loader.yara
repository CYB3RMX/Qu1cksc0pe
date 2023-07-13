rule MAL_Msil_Net_NixImports_Loader {
   meta:
      description = "Detects NixImports .NET loader"
      author = "dr4k0nia"
      date = "2023-05-21"
      reference = "https://github.com/dr4k0nia/NixImports"
   strings:
      $op_pe = {C2 95 C2 97 C2 B2 C2 92 C2 82 C2 82 C2 8E C2 82 C2 82 C2 82 C2 82 C2 86 C2 82} // PE magic
      $op_delegate = {20 F0 C7 FF 80 20 83 BF 7F 1F 14 14} // delegate initialization arguments

      // Imports that will be present due to HInvoke
      $a1 = "GetRuntimeProperties" ascii fullword
      $a2 = "GetTypes" ascii fullword
      $a3 = "GetRuntimeMethods" ascii fullword
      $a4 = "netstandard" ascii fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 3MB
      and all of ($a*)
      and 2 of ($op*)
}
