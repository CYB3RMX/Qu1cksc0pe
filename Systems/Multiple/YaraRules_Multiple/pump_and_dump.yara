rule PK_PUMP_AND_DUMP
{
   meta:
       date = "2023-03-08"
       author = "Will Metcalf @node5"
       refrence = "https://www.youtube.com/watch?v=9EcjWd-O4jI"
       description = "Walks Zip Central Directory filename entries looking for abused extension then checks for a file that's at least 25M and then check to see how much uncompressed size is vs compressed size"
       score = 90
   strings:
       $zipheader = { 50 4B 03 04 }
       $cdirfh = {50 4B 01 02}
       $s1 = ".vbs" ascii wide nocase
       $s2 = ".jse" ascii wide nocase
       $s3 = ".vbe" ascii wide nocase
       $s4 = ".bat" ascii wide nocase
       $s5 = ".wsf" ascii wide nocase
       $s6 = ".cmd" ascii wide nocase
       $s7 = ".hta" ascii wide nocase
       $s8 = ".xsl" ascii wide nocase
       $s9 = ".js" ascii wide nocase
       $s10 = ".wsc" ascii wide nocase
       $s11 = ".vbs" ascii wide nocase
       $s12 = ".jse" ascii wide nocase
       $s13 = ".vbe" ascii wide nocase
       $s14 = ".vbs" ascii wide nocase
       $s15 = ".msi" ascii wide nocase
       $s16 = ".ps1" ascii wide nocase
       $s17 = ".exe" ascii wide nocase
       $s18 = ".sct" ascii wide nocase
       $s19 = ".scr" ascii wide nocase
       $s20 = ".bat" ascii wide nocase
       $s21 = ".wsf" ascii wide nocase
       $s23 = ".cmd" ascii wide nocase
       $s24 = ".dll" ascii wide nocase
       $s25 = ".hta" ascii wide nocase
       $s26 = ".xsl" ascii wide nocase
       $s27 = ".lnk" ascii wide nocase
       $s28 = ".pif" ascii wide nocase
       $s29 = ".cpl" ascii wide nocase
       $s30 = ".ocx" ascii wide nocase
       $s31 = ".wsh" ascii wide nocase
       $s32 = ".doc" ascii wide nocase
       $s33 = ".xls" ascii wide nocase
       $s34 = ".rtf" ascii wide nocase
       $s35 = ".csv" ascii wide nocase
       $s36 = ".slk" ascii wide nocase
       $s37 = ".mht" ascii wide nocase
   condition:
         $zipheader at 0 and for any i in (1..#cdirfh) : ( for any of ($s*) :($ in (((@cdirfh[i]+46) + (uint16(@cdirfh[i]+28) -4))..((@cdirfh[i]+46) + (uint16(@cdirfh[i]+28))))) and (uint32(@cdirfh[i]+24) > 26214400) and ((uint32(@cdirfh[i]+20) * 200) < uint32(@cdirfh[i]+24)))
}
