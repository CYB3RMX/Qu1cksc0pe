rule Suspicious_Macro_Presence {
    meta:
        description = "This rule detects common malicious/suspicious implementations."
        author = "Mehmet Ali Kerimoglu (CYB3RMX)"
        date = "2023-04-02"
    strings:
        $m1 = "AutoOpen" wide ascii
        $m2 = "svchost.exe" wide ascii
        $m3 = "CreateObject" wide ascii
        $m4 = "WScript.Shell" wide ascii
        $m5 = "Scripting.FileSystemObject" wide ascii
        $m6 = "GetSpecialFolder" wide ascii
        $m7 = "Microsoft.XMLHTTP" wide ascii
        $m8 = ".exe" wide ascii
        $m9 = "ShellExecute" wide ascii
        $m10 = "Shell" wide ascii
        $m11 = ".ps1" wide ascii
        $m12 = ".hta" wide ascii
        $m13 = ".bin" wide ascii
        $m14 = ".class" wide ascii
        $m15 = "Environ" wide ascii
        $m16 = "cmd /c" wide ascii
    condition:
        any of them
}