import "androguard"
import "file"
import "cuckoo"


rule TrojanCajino
{
    meta:
   description = "Trojan which uses the Chinese search engine Baidu"


    strings:
        $a = "com.baidu.android.pushservice.action.MESSAGE"
        $b = "com.baidu.android.pushservice.action.RECEIVE" 
        $c = "com.baidu.android.pushservice.action.notification.CLICK"
        
      
    condition:
        $a and $b and $c
}