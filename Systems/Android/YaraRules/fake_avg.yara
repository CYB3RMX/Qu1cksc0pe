import "androguard"

rule fake_AVG {
    meta:
        description = "Detects a fake AVG Antivirus APK which contains adware."
        in_the_wild = true

    strings:
        $a = "https://mir-s3-cdn-cf.behance.net/project_modules/disp/3fd50115627063.562951a013590.jpg"
    
    condition:
        $a and
        androguard.app_name("AVG AntiVirus 2020 for Android Security FREE") and
        androguard.permission(/android.permission.INTERNET/) and
        androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
        androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
        androguard.certificate.sha1("6d0e7c4e30bfdb012bb6272a483434f60f41e7e0") and
        androguard.package_name("com.liudev.simplecakerecipes")
}