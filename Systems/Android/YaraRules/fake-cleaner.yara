import "file"
import "cuckoo"
import "androguard"

rule cleaner
{
	meta:
		description = "Determine if apk is a fake cleaner"
		sample = "32741c74508b5efaeada5d68bda3ddf53124331c22dd0b89b5b89647de1ce070"
		
	condition:
		androguard.app_name("Super Clean Master") and 
		not androguard.certificate.sha1("63f1eae14e454ee2d1ea7923853f93e788dd00e8")
}