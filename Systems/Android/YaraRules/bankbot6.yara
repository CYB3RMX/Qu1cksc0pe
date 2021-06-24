import "androguard"
import "file"

rule : BankBot_Trojan
{
    meta:
        sample = "61e49ea8ac3572e344c27742a2d53266df15266d0163470bbb56e5cd7ad78a4b"
        description = "This rule is for detecting BankBot-Trojan variant."
        author = "CYB3RMX"
    strings:
        $str1 = "wdc.rejg9r45.lzeg9rj.bot.PermissionsActivity"
    condition:
        file.md5("86a3403d7a9b5a70b5ab1074e6faea47") or
        (androguard.permission(/android.permission.SEND_SMS/) or androguard.permission(/android.permission.READ_SMS/)) and
        any of $str*
}
