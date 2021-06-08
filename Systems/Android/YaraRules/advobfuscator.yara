rule avdobfuscator : obfuscator
{
  meta:
    description = "AVDobfuscator"
    url         = "https://github.com/andrivet/ADVobfuscator"

  strings:
    $o1 = "ObfuscatedAddress"
    $o3 = "ObfuscatedCall"
    $o4 = "ObfuscatedCallP"
    $o5 = "ObfuscatedCallRet"
    $o6 = "ObfuscatedCallRetP"
    $o7 = "ObfuscatedFunc"

    //$elf_magic = { 7F 45 4C 46 }

  condition:
    1 of ($o*) //and $elf_magic at 0
}