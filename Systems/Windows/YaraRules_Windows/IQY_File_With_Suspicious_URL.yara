rule IQY_File_With_Suspicious_URL
{
    meta:
        Author = "InQuest Labs"
        Reference = "https://www.inquest.net/"
        Description = "Detects suspicious IQY Files using URLs associated with suspicious activity such as direct IP address URLs, URL shorteners, and file upload/download providers."
        Severity = "5"

    strings:
        /*
           match WEB on the first line of a file
           takes into account potential whitespace before or after case-insensitive "WEB" string
        */
         $web =/^[ \t]*WEB[ \t]*(\x0A|\x0D\x0A)/ nocase

        /* match any http or https URL using a direct IP address */
        $aa = /https?:\/\/((1?[0-9]{1,2}|25[0-5]|2[0-4][0-9])[.]){3}((1?[0-9]{1,2}|25[0-5]|2[0-4][0-9]))/

        /* file upload/download providers */
        $a2  = /https?:\/\/[^\.]*dropbox\.com\/sh?\// nocase
        $a4  = /https?:\/\/[^\.]*sendspace\.com\/./ nocase
        $a5  = /https?:\/\/[^\.]*bvp\.16mb\.com\/./ nocase
        $a6  = /https?:\/\/[^\.]*file\.io\/./ nocase
        $a7  = /https?:\/\/[^\.]*wetransfer\.com\/./ nocase
        $a8  = /https?:\/\/[^\.]*uploadcare\.com\/./ nocase
        $a9  = /https?:\/\/[^\.]*uploadfiles\.io\/./ nocase
        $a10 = /https?:\/\/[^\.]*filedropper\.com\/./ nocase
        $a11 = /https?:\/\/[^\.]*filefactory\.com\/./ nocase
        $a12 = /https?:\/\/[^\.]*doko\.moe\/./ nocase

        /* URL shorteners */
        $a109 = /https?:\/\/(www\.)?a\.gd\/./ nocase
        $a110 = /https?:\/\/(www\.)?binged\.it\/./ nocase
        $a112 = /https?:\/\/(www\.)?budurl\.com\/./ nocase
        $a113 = /https?:\/\/(www\.)?chilp\.it\/./ nocase
        $a114 = /https?:\/\/(www\.)?cli\.gs\/./ nocase
        $a115 = /https?:\/\/(www\.)?fon\.gs\/./ nocase
        $a117 = /https?:\/\/(www\.)?fwd4\.me\/./ nocase
        $a118 = /https?:\/\/(www\.)?hex\.io\/./ nocase
        $a119 = /https?:\/\/(www\.)?hurl\.ws\/./ nocase
        $a120 = /https?:\/\/(www\.)?is\.gd\/./ nocase
        $a121 = /https?:\/\/(www\.)?kl\.am\/./ nocase
        $a122 = /https?:\/\/(www\.)?short\.ie\/./ nocase
        $a123 = /https?:\/\/(www\.)?short\.to\/./ nocase
        $a124 = /https?:\/\/(www\.)?sn\.im\/./ nocase
        $a125 = /https?:\/\/(www\.)?snipr\.com\/./ nocase
        $a126 = /https?:\/\/(www\.)?snipurl\.com\/./ nocase
        $a127 = /https?:\/\/(www\.)?snurl\.com\/./ nocase
        $a130 = /https?:\/\/(www\.)?to\.ly\/./ nocase
        $a131 = /https?:\/\/(www\.)?tr\.im\/./ nocase
        $a132 = /https?:\/\/(www\.)?tweetburner\.com\/./ nocase
        $a133 = /https?:\/\/(www\.)?twurl\.nl\/./ nocase
        $a134 = /https?:\/\/(www\.)?ub0\.cc\/./ nocase
        $a135 = /https?:\/\/(www\.)?ur1\.ca\/./ nocase
        $a136 = /https?:\/\/(www\.)?urlborg\.com\/./ nocase
        $a137 = /https?:\/\/(www\.)?tiny\.cc\/./ nocase
        $a138 = /https?:\/\/(www\.)?lc\.chat\/./ nocase
        $a139 = /https?:\/\/(www\.)?soo\.gd\/./ nocase
        $a140 = /https?:\/\/(www\.)?s2r\.co\/./ nocase
        $a141 = /https?:\/\/(www\.)?clicky\.me\/./ nocase
        $a142 = /https?:\/\/(www\.)?bv\.vc\/./ nocase
        $a143 = /https?:\/\/(www\.)?s\.id\/./ nocase
        $a144 = /https?:\/\/(www\.)?smarturl\.it\/./ nocase
        $a145 = /https?:\/\/(www\.)?tiny\.pl\/./ nocase
        $a146 = /https?:\/\/(www\.)?x\.co\/./ nocase

    condition:
        $web at 0 and 1 of ($a*)
}
