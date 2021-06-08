import "androguard"
rule android_coinhive_fake_hack_app {
  meta:
		description = "This rule detects Android Fake App, that uses Coinhive"
		author = "Corsin Camichel, @cocaman"
		version = "2018-01-07"
		in_the_wild = true
    tlp = "green"

  strings:
    $string_1 = "Jakaminen:"
    $string_2 = "Hack"
    $string_3 = "initialActivityCount"

  condition:
  	all of ($string_*)

}