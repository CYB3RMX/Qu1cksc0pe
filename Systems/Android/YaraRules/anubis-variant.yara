import "androguard"

rule AnubisVariant : Bankbot
{
    meta:
        description = "Anubis Variant : Bankbot"
        hash = "61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81"
        in_the_wild = true
    strings:
        $str1 = "/o1o/a1.php" nocase
        $str2 = "/o1o/a3.php" nocase
        $str3 = "/o1o/a12.php" nocase
    condition:
        2 of ($str*)
        and
           (
               androguard.permission(/android.permission.RECEIVE_SMS/) or 		androguard.permission(/android.permission.READ_SMS/)
           )
}