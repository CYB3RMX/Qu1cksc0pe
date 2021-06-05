rule Banker:Gugi
{
	meta:
		description = "Ruleset to detect Gugi banker, more information @ https://medium.com/@entdark_/analyzing-an-android-banker-3849c9e4b6a9#.ckfr8afc8"
		sample = "afa13a98f31cdd4a847473d689747d6f1eec4151e0ae1c5db011bd931ba984ea"

	strings:
		$a = "tele2-rf.com:3000"
		$b = "create table settings(client_id integer,client_password TEXT,need_admin integer,need_card integer,first_bank integer,need_sber integer,need_tinkoff integer,need_vtb integer,need_alpha integer,need_raiff integer,server TEXT,filter TEXT,exist_bank_app integer);"

	condition:
		$a and $b
	
}