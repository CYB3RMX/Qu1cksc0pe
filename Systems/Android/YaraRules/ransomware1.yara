import "androguard"
import "file"
import "cuckoo"


rule ransomware : official
{

	strings:
		$a = "locknow" 
		$b = "onDisableRequest"
		$c = "bitcoin"
		$e = "resetpassword"

	condition:
		androguard.permission(/android.permission.BIND_DEVICE_ADMIN/) and
		$a and $b and $c and $e
		
}