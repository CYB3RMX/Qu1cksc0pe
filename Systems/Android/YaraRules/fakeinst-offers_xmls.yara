import "androguard"
rule FakeInst_offers_xmls
{
	meta:
        description = "FakeInst evidences offers XML"	
	strings:
		$0 = "strings.xml" wide ascii
		$1 = "app_name" wide ascii
		$2 = "apps_dir_wasnt_created" wide ascii
		$3 = "dialog_file_downloads_text" wide ascii
		$4 = "dialog_no_button" wide ascii
		$5 = "dialog_yes_button" wide ascii
		$6 = "download_file" wide ascii
		$7 = "error_sms_sending" wide ascii
		$8 = "full_offerts_text" wide ascii
		$9 = "i_disagree_offert" wide ascii
   	condition:
		all of them
}