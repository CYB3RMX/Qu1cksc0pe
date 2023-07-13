rule MAL_MSIL_NET_TyphonLogger_Jul23 {
   meta:
      author = "dr4k0nia"
      description = "Detects TyphonLogger .NET payloads"
      date = "11/07/2023"
      hash = "fc8733c217b49ca14702a59a637efc7dba6a2993d57e67424513ce2f5e9d8ed8"
   strings:
      $sa1 = "SetWindowsHookEx" ascii fullword
      $sa2 = "iphlpapi.dll" ascii fullword
      $sa3 = "SendARP" ascii fullword
      $sa4 = "costura.bouncycastle.crypto.dll.compressed" ascii fullword

      $op1 = {51 32 46 79 64 47 55 67 51 6D 78 68 62 6D 4E 6F 5A 53 42 44 59 58 4A 6B} // raw content of CC Helper array
      $op2 = {53 57 35 7A 64 47 45 67 55 47 46 35 62 57 56 75 64 43 42 44 59 58 4A 6B} // raw content of CC Helper array
      $op3 = {20 25 32 C4 C1 35 4C 11 06 20 6B 6D AC 1D 35 1D 11 06 20 4B A6 CA 11 3B 59 01 00 00 11 06 20 6B 6D AC 1D} // string comparison CIL

      $sx = "New Projects\\EmeraldLogger\\EmeraldLogger\\obj\\" ascii
   condition:
      uint16(0) == 0x5a4d
      and ($sx or (all of ($sa*) and 2 of ($op*)))
}
