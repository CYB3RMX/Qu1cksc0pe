rule Embedded_PE
{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "Discover embedded PE files, without relying on easily stripped/modified header strings."
    strings:
        $mz = { 4D 5A 90 00 } // 4D 5A gives false positives so I changed it to 4D 5A 90 00
    condition:
        for any i in (1..#mz):
        (
            @mz[i] != 0 and uint32(@mz[i] + uint32(@mz[i] + 0x3C)) == 0x00004550
        )
}
