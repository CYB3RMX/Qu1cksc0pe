rule AirPush
{
	meta:
        description = "Evidences of AirPush Adware SDK."
	strings:
		$1 = "api.airpush.com/dialogad/adclick.php"
		$2 = "Airpush Ads require Android 2.3"
   	condition:
    	1 of them
}