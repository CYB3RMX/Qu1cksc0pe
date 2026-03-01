rule macOS_LaunchAgent_Persistence
{
    meta:
        description = "Detects LaunchAgent/Daemon persistence strings in Mach-O binaries"
        author      = "Qu1cksc0pe"
        category    = "Persistence"
    strings:
        $la1 = "/Library/LaunchAgents/" ascii wide
        $la2 = "/Library/LaunchDaemons/" ascii wide
        $la3 = "~/Library/LaunchAgents/" ascii wide
        $la4 = "com.apple.launchd" ascii wide
        $la5 = "StartupItems" ascii wide
        $la6 = "SMLoginItemSetEnabled" ascii wide
        $la7 = "LSSharedFileListInsertItemURL" ascii wide
        $la8 = "kSMDomainUserLaunchd" ascii wide
    condition:
        uint32(0) == 0xFEEDFACF or uint32(0) == 0xFEEDFACE or uint32(0) == 0xCAFEBABE
        and any of them
}

rule macOS_Crontab_Persistence
{
    meta:
        description = "Detects cron-based persistence in Mach-O binaries"
        author      = "Qu1cksc0pe"
        category    = "Persistence"
    strings:
        $c1 = "crontab" ascii wide
        $c2 = "/etc/cron" ascii wide
        $c3 = "cron.d" ascii wide
        $c4 = "/var/spool/cron" ascii wide
    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xFEEDFACE or uint32(0) == 0xCAFEBABE)
        and any of them
}
