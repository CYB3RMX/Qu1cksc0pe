rule RustyStealer_Detect {
    meta:
        author = "Mehmet Ali Kerimoglu (@CYB3RMX)"
        description = "This rule detects RustyStealer patterns."
        reference = "https://github.com/CYB3RMX/Qu1cksc0pe"
        date = "07/07/2023"
    strings:
        $rusty1 = ".cargo" ascii wide
        $rusty2 = "rust_panic" ascii wide
        $rusty3 = "rustc" ascii wide
        $pattern1 = "C:\\Users\\peter\\OneDrive\\Documents\\Others\\CTHULHU\\target\\release\\deps\\rcrypt.pdb" ascii wide
        $pattern2 = "C:\\Users\\Administrator\\Desktop\\CK-567-master\\CK-567-master\\target\\release\\loader\\target\\release\\deps\\payload.pdb" ascii wide
        $pattern3 = "HELP_RECOVER_ALL_MY_FILES.txt" ascii wide
        $pattern4 = "C:\\Users\\peter\\.cargo" ascii wide
        $pattern5 = "C:\\Users\\runneradmin\\.cargo" ascii wide
        $pattern6 = "C:\\Users\\Administrator\\.cargo" ascii wide
        $pattern7 = "D:\\rust\\icojz\\target\\release\\deps\\mh3242.pdb" ascii wide
        $pattern8 = "conn.ping_pong" ascii wide
        $pattern9 = "\\Device\\Afd\\Mio" ascii wide
        $pattern10 = "D:\\rust\\xinjzq\\target\\release\\deps\\ai360.pdb" ascii wide
        $pattern11 = "uespemosarenegylmodnarodsetybdet" ascii wide
        $pattern12 = "1.3.6.1.5.5.7.3.1" ascii wide
        $pattern13 = "1.3.6.1.4.1.311.10.3.3" ascii wide
        $pattern14 = "C:\\Users\\user\\Documents\\Project\\check_name\\target\\debug\\deps\\FingerPrint_disable_x64.pdb" ascii wide
        $pattern15 = "args.rscmd.exe" ascii wide
    condition:
        ((2 or all of ($rusty*)) and (3 or all of ($pattern*)))
}