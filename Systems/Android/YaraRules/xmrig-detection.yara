import "cuckoo"


rule xmrigStrings
{
    strings:
        $fee = "fee.xmrig.com" wide ascii
        $nicehash = "nicehash.com" wide ascii
        $minergate = "minergate.com" wide ascii
        $stratum = "stratum+tcp://" wide ascii


    condition:
       $fee and
       $nicehash and
       $minergate and
       $stratum 
}