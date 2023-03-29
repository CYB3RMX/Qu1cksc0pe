rule win_stealc_w0 {
   meta:
       malware = "Stealc"
       description = "Find standalone Stealc sample based on decryption routine or characteristic strings"
       source = "SEKOIA.IO"
       reference = "https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"
       classification = "TLP:CLEAR"
       hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"
       author = "crep1x"
       malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealc"
       malpedia_version = "20230221"
       malpedia_license = "CC BY-NC-SA 4.0"
       malpedia_sharing = "TLP:WHITE"
       malpedia_rule_date = "20230221"
       malpedia_hash = ""
   strings:
       $dec = { 55 8b ec 8b 4d ?? 83 ec 0c 56 57 e8 ?? ?? ?? ?? 6a 03 33 d2 8b f8 59 f7 f1 8b c7 85 d2 74 04 } //deobfuscation function

       $str01 = "------" ascii
       $str02 = "Network Info:" ascii
       $str03 = "- IP: IP?" ascii
       $str04 = "- Country: ISO?" ascii
       $str05 = "- Display Resolution:" ascii
       $str06 = "User Agents:" ascii
       $str07 = "%s\\%s\\%s" ascii

   condition:
       uint16(0) == 0x5A4D and ($dec or 5 of ($str*))
}