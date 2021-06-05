rule auto_responder
{
 		meta:
        description = "This is rule for auto responder through whatsapp"
    strings:
		$a = "RemoteInput"
        $b = "setComponentEnabledSetting"
        $c = "onNotificationPosted"
        $d = "com.whatsapp"
    condition:
        $a and $b and $c and $d
}