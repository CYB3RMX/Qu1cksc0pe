rule bankingapps
{
	strings:
	  $ = "com.ingbanktr.ingmobil"
	  $ = "com.ing.mobile"
	  $ = "au.com.ingdirect.android"
	  $ = "de.ing_diba.kontostand"
	  $ = "com.ing.diba.mbbr2"
	  $ = "com.IngDirectAndroid"
	  $ = "pl.ing.ingmobile"
	condition:
		1 of them
}