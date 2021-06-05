rule AirPush
{
	meta:
        description = "Evidences of AirPush Adware SDK. v1.2 20160208"
	strings:
    	$1 = "AirpushAdActivity.java"
    	$2 = "&airpush_url="
		$3 = "getAirpushAppId"
		$4 = "Airpush SDK is disabled"
		$5 = "api.airpush.com/dialogad/adclick.php"
		$6 = "res/layout/airpush_notify.xml"
		$7 = "Airpush Ads require Android 2.3"
		$8 = "AirpushInlineBanner"
		$9 = "AirpushAdEntity"
   	condition:
    	1 of them
}