rule NativeCode
{
    meta:
    	author = "packmad - https://twitter.com/packm4d"
		date = "2019/11/25"
		description = "This rule detects APKs containing native libs"
    strings:
        $lib_arm = /lib\/arm(eabi|64)-v[0-9a-zA-Z]{2}\//
        $lib_x86 = /lib\/x86(_64)?\//
		$lib_ass = /assets\/[!-~]+\.so/
    condition:
        1 of ($lib_*)
}