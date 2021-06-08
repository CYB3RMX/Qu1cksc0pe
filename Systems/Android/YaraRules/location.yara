import "androguard"

rule users_location
{	
	meta:
		sample = "401193787f23126097d4b7600ce8e7d118db24023039897f4a292eab2d87a499"

	strings:
		$string1 = "android/location/Location/"
		
	condition:
		$string1 and (
		androguard.permission(/ACCESS_FINE_LOCATION/) or
		androguard.permission(/ACCESS_COARSE_LOCATION/)
		)
}

rule get_deviceId
{
	strings:
		$string2 = "getdeviceId"
		$string3 = "android/telephony/TelephonyManager"
		
	condition:
		$string2 and $string3
}