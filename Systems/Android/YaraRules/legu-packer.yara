rule legu : packer
{
    meta:
		description = "Identify Legu Packer"
	strings:
		$a = "assets/toversion"
		$b = "assets/0OO00l111l1l"
		$c = "assets/0OO00oo01l1l"
		$d = "assets/o0oooOO0ooOo.dat"
	condition:
	    // previous: all of them
		$b and ($a or $c or $d)

}