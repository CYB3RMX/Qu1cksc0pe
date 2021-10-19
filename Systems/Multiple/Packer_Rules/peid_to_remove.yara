
rule Morphine_v1_2___v1_3
{
strings:
		$a0 = { FF 25 34 ?? 5A 00 8B C0 FF 25 38 ?? 5A 00 8B C0  }

condition:
		$a0 at entrypoint
}
	
	
rule SEA_AXE_v2_2
{
strings:
		$a0 = { FC BC ?? ?? 0E 1F A3 ?? ?? E8 ?? ?? A1 ?? ?? 8B ?? ?? ?? 2B C3 8E C0 B1 03 D3 E3 8B CB BF ?? ?? 8B F7 F3 A5  }

condition:
		$a0 at entrypoint
}
	
	
rule Pohernah_1_0_0___by_Kas
{
strings:
		$a0 = { 58 60 E8 00 00 00 00 5D 81 ED 20 25 40 00 8B BD 86 25 40 00 8B 8D 8E 25 40 00 6B C0 05 83 F0 04 89 85 92 25 40 00 83 F9 00 74 2D 81 7F 1C AB 00 00 00 75 1E 8B 77 0C 03 B5 8A 25 40 00 31 C0 3B 47 10 74 0E 50 8B 85 92 25 40 00 30 06 58 40 46 EB ED 83 C7 28 49 EB CE 8B 85 82 25 40 00 89 44 24 1C 61 FF E0  }

condition:
		$a0 at entrypoint
}
	
	
rule PCrypt_v3_51
{
strings:
		$a0 = { 50 43 52 59 50 54 FF 76 33 2E 35 31 00 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptor_V1_6c____Vaska_____Sign_By_fly
{
strings:
		$a0 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3  }

condition:
		$a0 at entrypoint
}
	
	
rule CRYPT_Version_1_7__c__Dismember
{
strings:
		$a0 = { 0E 17 9C 58 F6 ?? ?? 74 ?? E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Quake_518
{
strings:
		$a0 = { 1E 06 8C C8 8E D8 ?? ?? ?? ?? ?? ?? ?? B8 21 35 CD 21 81  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v1_01b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44  }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor_v1_4_5_1____CGSoftLabs
{
strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? ?? 05 00 ?? ?? ?? A3 08 ?? ?? ?? A1 08 ?? ?? ?? B9 81 ?? ?? ?? 2B 48 18 89 0D 0C ?? ?? ?? 83 3D 10 ?? ?? ?? 00 74 16 A1 08 ?? ?? ?? 8B 0D 0C ?? ?? ?? 03 48 14 89 4D CC  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_4_2____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 C3 27 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Eddie_based_1745
{
strings:
		$a0 = { E8 ?? ?? 5E 81 EE ?? ?? FC ?? 2E ?? ?? ?? ?? 4D 5A ?? ?? FA ?? 8B E6 81 ?? ?? ?? FB ?? 3B ?? ?? ?? ?? ?? 50 06 ?? 56 1E 8B FE 33 C0 ?? 50 8E D8  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_WWPack32_1_x_____emadicius
{
strings:
		$a0 = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 20 64 65 63 6F 6D 70 72 65 73 73 69 6F 6E 20 72 6F 75 74 69 6E 65 20 76 65 72 73 69 6F 6E 20 31 2E 31 32 0D 0A 28 63 29 20 31 39 39 38 20 50 69 6F 74 72 20 57 61 72 65 7A 61 6B 20 61 6E 64 20 52 61 66 61 6C 20 57 69 65 72 7A 62 69 63 6B 69 0D 0A 0D 0A 5D 5B 90 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_4_1____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 01 ?? E8 2A 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 C3 27 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Native_UD_Packer_1_1__Modded_Poison_Ivy_Shellcode_____okkixot
{
strings:
		$a0 = { 31 C0 31 DB 31 C9 EB 0E 6A 00 6A 00 6A 00 6A 00 FF 15 28 41 40 00 FF 15 94 40 40 00 89 C7 68 88 13 00 00 FF 15 98 40 40 00 FF 15 94 40 40 00 81 C7 88 13 00 00 39 F8 73 05 E9 84 00 00 00 6A 40 68 00 10 00 00 FF 35 04 30 40 00 6A 00 FF 15 A4 40 40 00 89 C7 FF 35 04 30 40 00 68 CA 10 40 00 50 FF 15 A8 40 40 00 6A 40 68 00 10 00 00 FF 35 08 30 40 00 6A 00 FF 15 A4 40 40 00 89 C6 68 00 30 40 00 FF 35 04 30 40 00 57 FF 35 08 30 40 00 50 6A 02 FF 15 4E 41 40 00 6A 00 6A 00 6A 00 56 6A 00 6A 00 FF 15 9C 40 40 00 50 6A 00 6A 00 6A 11 50 FF 15 4A 41 40 00 58 6A FF 50 FF 15 AC 40 40 00 6A 00 FF 15 A0 40  }

condition:
		$a0 at entrypoint
}
	
	
rule PAK_SFX_Archive
{
strings:
		$a0 = { 55 8B EC 83 ?? ?? A1 ?? ?? 2E ?? ?? ?? 2E ?? ?? ?? ?? ?? 8C D7 8E C7 8D ?? ?? BE ?? ?? FC AC 3C 0D  }

condition:
		$a0 at entrypoint
}
	
	
rule NsPack_V1_1____LiuXingPing_____Sign_By_fly
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule NSIS_Installer_____NullSoft
{
strings:
		$a0 = { 83 EC 20 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? ?? ?? C6 44 24 14 20 FF 15 30 70 40 00 53 FF 15 80 72 40 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE  }

condition:
		$a0 at entrypoint
}
	
	
rule MinGW_v3_2_x__Dll_main_
{
strings:
		$a0 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 96 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00 00 00 EB EB 8D B4 26 00 00 00 00 85 C0 75 D0 E8 47 00 00 00 EB C9 90 8D 74 26 00 C7 04 24 80 00 00 00 E8 F4 05 00 00 A3 00 30 00 10 85 C0 74 1A C7 00 00 00 00 00 A3 10 30 00 10 E8 3B 02 00 00 E8 C6 01 00 00 E9 75 FF FF FF E8 BC 05 00 00 C7 00 0C 00 00 00 31 C0 EB 98 89 F6 55 89 E5 83 EC 08 89 5D FC 8B 15 00 30 00 10 85 D2 74 29 8B 1D 10 30 00 10 83 EB 04 39 D3 72 0D 8B 03 85 C0 75 2A 83 EB 04 39 D3 73 F3 89 14 24 E8 6B 05 00 00 31 C0 A3 00 30 00 10 C7 04 24 00 00 00 00 E8 48 05 00 00 8B 5D FC 89 EC 5D C3  }

condition:
		$a0 at entrypoint
}
	
	
rule SVK_Protector_v1_051
{
strings:
		$a0 = { 60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 00 00 00 00 5D 81 ED 10 00 00 00 EB 03 C7 84 E9 64 A0 23 00 00 00 EB  }

condition:
		$a0 at entrypoint
}
	
	
rule __Six_to_Four__v1_0
{
strings:
		$a0 = { 50 55 4C 50 83 ?? ?? FC BF ?? ?? BE ?? ?? B5 ?? 57 F3 A5 C3 33 ED  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Encrypt_1_0____Liwuyue
{
strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D 0F 05 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 5D EC 8B 41 18 8B C8 49 85 C9 72 5A 41 33 C0 8B D8 C1 E3 02 03 DA 8B 3B 03 3E 81 3F 47 65 74 50 75 40 8B DF 83 C3 04 81 3B 72 6F 63 41 75 33 8B DF 83 C3 08 81 3B 64 64 72 65 75 26 83 C7 0C 66 81 3F 73 73  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__CodeSafe_2_0______Anorganix
{
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule STNPEE_1_13
{
strings:
		$a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 97 3B 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule AcidCrypt
{
strings:
		$a0 = { 60 B9 ?? ?? ?? 00 BA ?? ?? ?? 00 BE ?? ?? ?? 00 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB  }
	$a1 = { BE ?? ?? ?? ?? 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule UPX_Inliner_v1_0_by_GPcH
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 B1 FE FF FF 2B D0 89 95 B1 FE FF FF 01 95 C9 FE FF FF 8D B5 E5 FE FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 05 FF FF FF 85 C0 0F 84 06 03 00 00 89 85 C5 FE FF FF E8 00 00 00 00 5B B9 31 89 40 00 81 E9 2E 86 40 00 03 D9 50 53 E8 3D 02 00 00 61 03 BD A9 FE FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 09 FF FF FF FF B5 05 FF FF FF 56 57 FF 95 C5 FE FF FF 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB CE 68 00 80 00 00 6A 00 FF B5 C5 FE FF FF FF 95 09 FF FF FF 8D  }

condition:
		$a0 at entrypoint
}
	
	
rule Upx_Lock_1_0___1_2_____CyberDoom___Team_X___BoB___BobSoft
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61  }

condition:
		$a0 at entrypoint
}
	
	
rule Shrink_v1_0
{
strings:
		$a0 = { 50 9C FC BE ?? ?? BF ?? ?? 57 B9 ?? ?? F3 A4 8B ?? ?? ?? BE ?? ?? BF ?? ?? F3 A4 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_0_20_beta____Dwing
{
strings:
		$a0 = { BE 88 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____Borland_Delphi___Microsoft_Visual_C___
{
strings:
		$a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13  }
	$a1 = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 ?? ?? 77 EB 02 CD 20 5E EB 02 CD 20 2B F7  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PluginToExe_v1_00____BoB___BobSoft
{
strings:
		$a0 = { E8 00 00 00 00 29 C0 5D 81 ED D1 40 40 00 50 FF 95 B8 40 40 00 89 85 09 40 40 00 FF 95 B4 40 40 00 89 85 11 40 40 00 50 FF 95 C0 40 40 00 8A 08 80 F9 22 75 07 50 FF 95 C4 40 40 00 89 85 0D 40 40 00 8B 9D 09 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 0D 40 40 00 6A 00 81 C3 ?? ?? ?? 00 FF D3 83 C4 10 FF 95 B0 40 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Packman_v1_0____Brandon_LaCombe
{
strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA 8B E8 C6 06 E9 8B 43 0C 89 46 01 6A 04 68 00 10 00 00 FF 73 08 51 FF 55 08 8B  }

condition:
		$a0 at entrypoint
}
	
	
rule ___________V1_0____tjszlqq_____Sign_By_fly___20090823
{
strings:
		$a0 = { E9 15 AC 00 00 00 00 E9 ED 3A 01 00 00 00 E9 A1 9A 01 00 00 00 E9 CD 76 02 00 00 00 E9 8D FA 01 00 00 00 E9 CB 04 00 00 00 00 E9 A4 9F 00 00 00 00 66 B8 00 02 66 85 C0 0F 85 F0 5E 04 00 00 00 00 00 00 00 00 00 66 B8 00 00 E9 73 8F 02 00 00 00 00 00 00 E9 1A 57 03 00 00 00 E9 35 4E 04 00 00 00 E9 74 9D 00 00 00 00 E9 44 4D 02 00 00 00 E9 9B F2 03 00 00 00 E9 8B 63 03 00 00 00 E9 06 95 01 00 00 00 E9 77 7D 03 00 00 00 B0 02 E9 74 BB 02 00 00 00 00 00 00 00 00 E9 3C E5 03 00 00 00 E9 F4 83 02 00 00 00 E9 9D 9F 00 00 00 00 E9 72 CB 00 00 00 00 E9 88 C2 00 00 00 00 E9 42 3B 04 00 00 00 E9 F4 4C 00 00 00 00 E9 B8 28 04 00 00 00 E9 0F 4F 00 00 00 00 66 83 E8 00 E9 02 F4 00 00 00 00 00 00 00 84 C0 E9 B9 90 01 00 00 00 00 00 00 00 00 E9 78 C5 02 00  }

condition:
		$a0 at entrypoint
}
	
	
rule yoda_s_Protector_V1_01____Ashkbiz_Danehkar_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED D5 E4 41 00 8B D5 81 C2 23 E5 41 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3  }

condition:
		$a0 at entrypoint
}
	
	
rule PEncrypt_v3_0
{
strings:
		$a0 = { E8 00 00 00 00 5D 81 ED 05 10 40 00 8D B5 24 10 40 00 8B FE B9 0F 00 00 00 BB ?? ?? ?? ?? AD 33 C3 E2 FA  }

condition:
		$a0 at entrypoint
}
	
	
rule MinGW_v3_2_x__Dll_mainCRTStartup_
{
strings:
		$a0 = { 55 89 E5 83 EC 08 6A 00 6A 00 6A 00 6A 00 E8 0D 00 00 00 B8 00 00 00 00 C9 C3 90 90 90 90 90 90 FF 25 38 20 00 10 90 90 00 00 00 00 00 00 00 00 FF FF FF FF 00 00 00 00 FF FF FF FF 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule App_Encryptor____Silent_Team
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 1F 1F 40 00 B9 7B 09 00 00 8D BD 67 1F 40 00 8B F7 AC  }

condition:
		$a0 at entrypoint
}
	
	
rule PCShrink_v0_40b
{
strings:
		$a0 = { 9C 60 BD ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 6A ?? FF ?? ?? ?? ?? ?? 50 50 2D  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__DEF_1_0______Anorganix
{
strings:
		$a0 = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_Scrambler_RC_v1_x
{
strings:
		$a0 = { 90 61 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF  }

condition:
		$a0 at entrypoint
}
	
	
rule PEiD_Bundle_V1_02_DLL____BoB___BobSoft
{
strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule DIET_v1_00__v1_00d
{
strings:
		$a0 = { BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC  }

condition:
		$a0 at entrypoint
}
	
	
rule StarForce_3_0____StarForce_Technology
{
strings:
		$a0 = { 68 ?? ?? ?? ?? FF 25 ?? ?? 63  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_v0_32_beta____Dwing
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32  }

condition:
		$a0 at entrypoint
}
	
	
rule SVK_Protector_v1_11
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 64 A0 23  }

condition:
		$a0 at entrypoint
}
	
	
rule PEBundle_v3_10
{
strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD ?? ?? ?? ?? 40 00 01  }

condition:
		$a0 at entrypoint
}
	
	
rule Crinkler_V0_3_V0_4____Rune_L_H_Stubbe_and_Aske_Simon_Christensen_____Sign_By_fly
{
strings:
		$a0 = { B8 00 00 42 00 31 DB 43 EB 58  }

condition:
		$a0 at entrypoint
}
	
	
rule HACKSTOP_v1_13
{
strings:
		$a0 = { 52 B8 ?? ?? 1E CD 21 86 E0 3D ?? ?? 73 ?? CD 20 0E 1F B4 09 E8 ?? ?? 24 ?? EA  }

condition:
		$a0 at entrypoint
}
	
	
rule HACKSTOP_v1_19
{
strings:
		$a0 = { 52 BA ?? ?? 5A EB ?? 9A ?? ?? ?? ?? 30 CD 21 ?? ?? ?? D6 02 ?? ?? CD 20 0E 1F 52 BA ?? ?? 5A EB  }

condition:
		$a0 at entrypoint
}
	
	
rule HACKSTOP_v1_18
{
strings:
		$a0 = { 52 BA ?? ?? 5A EB ?? 9A ?? ?? ?? ?? 30 CD 21 ?? ?? ?? FD 02 ?? ?? CD 20 0E 1F 52 BA ?? ?? 5A EB  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_SVKP_1_11_____emadicius
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 64 A0 23 00 00 00 83 C5 06 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule Hide_PE_1_01____BGCorp
{
strings:
		$a0 = { BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 F8 FF E2 0D 0A 2D 3D 5B 20 48 69 64 65 50 45 20 62 79 20 42 47 43 6F 72 70 20 5D 3D 2D  }

condition:
		$a0 at entrypoint
}
	
	
rule PECompact_v0_971___v0_976
{
strings:
		$a0 = { EB 06 68 C3 9C 60 E8 5D 55 5B 81 ED 8B 85 01 85 66 C7 85  }

condition:
		$a0 at entrypoint
}
	
	
rule E2C_by_DoP
{
strings:
		$a0 = { BE ?? ?? BF ?? ?? B9 ?? ?? FC 57 F3 A5 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_Full_Edition_1_17_iBox_rule__aPLib_____Ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 79 29 00 00 8D 9D 2C 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34  }

condition:
		$a0 at entrypoint
}
	
	
rule VProtector_V1_3X____vcasm_____Sign_By_fly
{
strings:
		$a0 = { E9 B9 16 00 00 55 8B EC 81 EC 74 04 00 00 57 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 10 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 FF FF C2 10 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Ninja_v1_0
{
strings:
		$a0 = { BE 5B 2A 40 00 BF 35 12 00 00 E8 40 12 00 00 3D 22 83 A3 C6 0F 85 67 0F 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90  }

condition:
		$a0 at entrypoint
}
	
	
rule Nullsoft_Install_System_v2_0
{
strings:
		$a0 = { 83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 68 68 92 40 00 56 FF D5 E8 6A FF FF FF 85 C0 0F 84 57 01 00 00 BE 20 E4 42 00 56 FF 15 68 70 40 00 68 5C 92 40 00 56 E8 9C 28 00 00 57 FF 15 BC 70 40 00 BE 00 40 43 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 40 43 00 22 A3 20 EC 42 00 75 0A C6 44 24 14 22 BE 01 40 43 00 FF 74 24 14 56 E8 8A 23 00 00 50 FF 15 80 71 40 00 8B F8 89 7C 24 18 EB 61 80 F9 20 75 06 40 80 38 20 74 FA 80 38 22 C6 44 24 14 20 75 06 40 C6 44 24 14 22 80 38 2F 75 31 40 80 38 53 75 0E 8A 48 01 80 C9 20 80 F9 20 75 03  }

condition:
		$a0 at entrypoint
}
	
	
rule NeoLite_v2_00
{
strings:
		$a0 = { 8B 44 24 04 23 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 FE 05 ?? ?? ?? ?? 0B C0 74  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Spin_v0_b
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 72 C8 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 26 E8 01 00 00 00 EA 5A 33 C9 8B 95 68 20 40 00 8B 42 3C 03 C2 89 85 76 20 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D 8A 20 40 00 8B 59 24 03 DA 8B 1B 89 9D 8E 20 40 00 53 8F 85 E2 1F 40 00 8D 85 92 20 40 00 6A 0C 5B 6A 17 59 30 0C 03 02 CB 4B 75 F8 40 8D 9D 41 8F 4E 00 50 53 81 2C 24 01 78 0E 00 FF B5 8A 20 40 00 C3 92 EB 15 68 BB ?? 00 00 00 B9 90 08 00 00 8D BD FF 20 40 00 4F 30 1C 39 FE CB E2 F9 68 1D 01 00 00 59 8D BD 2F 28 40 00 C0 0C 39 02 E2 FA 68 A0 20 40 00 50 01 6C 24 04 E8 BD 09 00 00 33 C0 0F 84 C0 08 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Soft_Defender_v1_1x____Randy_Li
{
strings:
		$a0 = { 74 07 75 05 ?? ?? ?? ?? ?? 74 1F 75 1D ?? 68 ?? ?? ?? 00 59 9C 50 74 0A 75 08 ?? 59 C2 04 00 ?? ?? ?? E8 F4 FF FF FF ?? ?? ?? 78 0F 79 0D  }

condition:
		$a0 at entrypoint
}
	
	
rule Solidshield_Protector_V1_X_DLL____Solidshield_Technologies_____Sign_By_fly
{
strings:
		$a0 = { 8B 44 24 08 48 75 0A FF 74 24 04 E8 ?? ?? ?? ?? 59 33 C0 40 C2 0C 00 55 8B EC 56 8B 75 08 85 F6 75 28 68 ?? ?? ?? ?? BE ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 59 59 6A ?? 68 ?? ?? ?? ?? 56 6A ?? FF ?? ?? ?? ?? ?? E9 80 00 00 00 83 FE 01 75 07 5E 5D E9 D2 F6 FF FF 83 FE 02 57 8B 7D 10 75 53 FF 75 24 FF 75 20 FF 75 1C FF 75 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? BE ?? ?? ?? ?? 56 57 E8 ?? ?? ?? ?? 83 C4 20 3C 01 75 04 8B C6 EB 6A 57 FF 75 0C E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 56 57 E8 ?? ?? ?? ?? 83 C4 14 3C 01 74 DF 6A 03 5E 83 FE 03 75 1B 57 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 6A 00 FF 15 ?? ?? ?? ?? 83 FE 04 75 0D FF 75 2C FF 75 28 E8 ?? ?? ?? ?? 59 59 83 FE 05 75 11 FF 75 30 FF 75 2C FF 75 28 E8 ?? ?? ?? ?? 83 C4 0C 33 C0 5F 5E 5D C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Xtreme_Protector_v1_06
{
strings:
		$a0 = { B8 ?? ?? ?? 00 B9 75 ?? ?? 00 50 51 E8 05 00 00 00 E9 4A 01 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 00 00 00 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46 12 D2 73 4F 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 DF 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 74 06 57 2B F8 8A 07 5F 88 07 47 BB 02 00 00 00 EB 9B B8 01 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 72 EA 2B C3 BB 01 00 00 00 75 28 B9 01 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C9 02 D2 75 05 8A 16 46 12 D2 72 EA 56 8B F7 2B F5 F3 A4 5E E9 4F FF FF FF 48 C1 E0 08 8A 06 46 8B E8 B9 01 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C9 02 D2 75 05 8A 16 46 12 D2 72 EA 3D 00 7D 00 00 73 1A 3D 00 05 00 00 72 0E 41 56 8B F7 2B F0 F3 A4 5E E9 0F FF FF FF 83 F8 7F 77 03 83 C1 02 56 8B F7 2B F0 F3 A4 5E E9 FA FE FF FF 8A 06 46 33 C9 C0 E8 01 74 17 83 D1 02 8B E8 56 8B F7 2B F0 F3 A4 5E BB 01 00 00 00 E9 D9 FE FF FF 2B 7C 24 28 89 7C 24 1C 61 C2 08 00 E9 ?? ?? ?? 00 E9 38 ?? ?? ?? 01  }

condition:
		$a0 at entrypoint
}
	
	
rule Xtreme_Protector_v1_05
{
strings:
		$a0 = { E9 ?? ?? 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v1_77
{
strings:
		$a0 = { 55 8B EC 6A FF 68 B0 71 40 00 68 6C 37 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule SuperDAT
{
strings:
		$a0 = { 55 8B EC 6A FF 68 40 F3 42 00 68 A4 BF 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 08 F2 42 00 33 D2 8A D4 89 15 60 42 43 00 8B C8 81 E1 FF 00 00 00 89 0D  }

condition:
		$a0 at entrypoint
}
	
	
rule SoftProtect____www_softprotect_by_ru
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? C7 00 00 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? 01  }

condition:
		$a0 at entrypoint
}
	
	
rule Inno_Setup_Module_Heuristic_Mode
{
strings:
		$a0 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 ?? 89 45 ?? E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule PEcrypt___by_archphase
{
strings:
		$a0 = { 55 8B EC 83 C4 E0 53 56 33 C0 89 45 E4 89 45 E0 89 45 EC ?? ?? ?? ?? 64 82 40 00 E8 7C C7 FF FF 33 C0 55 68 BE 84 40 00 64 FF 30 64 89 20 68 CC 84 40 00 ?? ?? ?? ?? 00 A1 10 A7 40 00 50 E8 1D C8 FF FF 8B D8 85 DB 75 39 E8 3A C8 FF FF 6A 00 6A 00 68 A0 A9 40 00 68 00 04 00 00 50 6A 00 68 00 13 00 00 E8 FF C7 FF FF 6A 00 68 E0 84 40 00 A1 A0 A9 40 00 50 6A 00 E8 ?? ?? ?? ?? E9 7D 01 00 00 53 A1 10 A7 40 00 50 E8 42 C8 FF FF 8B F0 85 F6 75 18 6A 00 68 E0 84 40 00 68 E4 84 40 00 6A 00 E8 71 C8 FF FF E9 53 01 00 00 53 6A 00 E8 2C C8 FF FF A3 ?? ?? ?? ?? 83 3D 48 A8 40 00 00 75 18 6A 00 68 E0 84 40 00 68 F8 84 40 00 6A 00 E8 43 C8 FF FF E9 25 01 00 00 56 E8 F8 C7 FF FF A3 4C A8 40 00 A1 48 A8 40 00 E8 91 A1 FF FF 8B D8 8B 15 48 A8 40 00 85 D2 7C 16 42 33 C0 8B 0D 4C A8 40 00 03 C8 8A 09 8D 34 18 88 0E 40 4A 75 ED 8B 15 48 A8 40 00 85 D2 7C 32 42 33 C0 8D 34 18 8A 0E 80 F9 01 75 05 C6 06 FF EB 1C 8D 0C 18 8A 09 84 ?? ?? ?? ?? ?? 00 EB 0E 8B 0D 4C A8 40 00 03 C8 0F B6 09 49 88 0E 40 4A 75 D1 8D ?? ?? ?? ?? E8 A5 A3 FF FF 8B 45 E8 8D 55 EC E8 56 D5 FF FF 8D 45 EC BA 18 85 40 00 E8 79 BA FF FF 8B 45 EC E8 39 BB FF FF 8B D0 B8 54 A8 40 00 E8 31 A6 FF FF BA 01 00 00 00 B8 54 A8 40 00 E8 12 A9 FF FF E8 DD A1 FF FF 68 50 A8 40 00 8B D3 8B 0D 48 A8 40 00 B8 54 A8 40 00 E8 56 A7 FF FF E8 C1 A1 FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule PESHiELD_v0_2___v0_2b___v0_2b2
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_V2_2____Alexey_Solodovnikov___StarForce____Sign_By_fly___2009408
{
strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD ?? ?? ?? ?? ?? ?? 83 BD 7D 04 00 00 00 89 9D 7D 04 00 00 0F 85 C0 03 00 00 8D 85 89 04 00 00 50 FF 95 09 0F 00 00 89 85 81 04 00 00 8B F0 8D 7D 51 57 56 FF 95 05 0F 00 00 AB B0 00 AE 75 FD 38 07 75 EE 8D 45 7A FF E0 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 56 69 72 74 75 61 6C 46 72 65 65 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 8B 9D 8D 05 00 00 0B DB 74 0A 8B 03 87 85 91 05 00 00 89 03 8D B5 BD 05 00 00 83 3E 00 0F 84 15 01 00 00 6A 04 68 00 10 00 00 68 00 18 00 00 6A 00 FF 55 51 89 85 53 01 00 00 8B 46 04 05 0E 01 00 00 6A 04 68 00 10 00 00 50 6A 00 FF 55 51 89 85 4F 01 00 00 56 8B 1E 03 9D 7D 04 00 00 FF B5 53 01 00 00 FF 76 04 50 53 E8 2D 05 00 00 B3 00 80 FB 00 75 5E FE 85 E9 00 00 00 8B 3E 03 BD 7D 04 00 00 FF 37 C6 07 C3 FF D7 8F 07 50 51 56 53 8B C8 83 E9 06 8B B5 4F 01 00 00 33 DB 0B C9 74 2E 78 2C AC 3C E8 74 0A EB 00 3C E9 74 04 43 49 EB EB 8B 06 EB 00 ?? ?? ?? 75 F3 24 00 C1 C0 18 2B C3 89 06 83 C3 05 83 C6 04 83 E9 05 EB CE 5B 5E 59 58 EB 08  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__MTE__non_encrypted_
{
strings:
		$a0 = { F7 D9 80 E1 FE 75 02 49 49 97 A3 ?? ?? 03 C1 24 FE 75 02 48  }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACK_v3_00__v3_01__Relocations_pack_
{
strings:
		$a0 = { BE ?? ?? BA ?? ?? BF ?? ?? B9 ?? ?? 8C CD 8E DD 81 ED ?? ?? 06 06 8B DD 2B DA 8B D3 FC  }

condition:
		$a0 at entrypoint
}
	
	
rule LamerStop_v1_0c__c__Stefan_Esser
{
strings:
		$a0 = { E8 ?? ?? 05 ?? ?? CD 21 33 C0 8E C0 26 ?? ?? ?? 2E ?? ?? ?? 26 ?? ?? ?? 2E ?? ?? ?? BA ?? ?? FA  }

condition:
		$a0 at entrypoint
}
	
	
rule mucki_s_protector_II____mucki_____Sign_By_fly
{
strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 6A 00 E8 85 C0 74 12 64 8B 3D 18 00 00 00 8B 7F 30 0F B6 47 02 85 C0 74 01 C3 C7 04 24 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 F7 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Private_Personal_Packer__PPP__V1_0_2____ConquestOfTroy_com_____Sign_By_fly
{
strings:
		$a0 = { E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 E8 D3 03 00 00 A3 20 37 00 10 50 6A 00 E8 DE 03 00 00 A3 24 37 00 10 FF 35 20 37 00 10 6A 00 E8 EA 03 00 00 A3 30 37 00 10 FF 35 24 37 00 10 E8 C2 03 00 00 A3 28 37 00 10 8B 0D 30 37 00 10 8B 3D 28 37 00 10 EB 09 49 C0 04 39 55 80 34 39 24 0B C9  }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDote_1_0_Beta____SIS_Team
{
strings:
		$a0 = { E8 BB FF FF FF 84 C0 74 2F 68 04 01 00 00 68 C0 23 60 00 6A 00 FF 15 08 10 60 00 E8 40 FF FF FF 50 68 78 11 60 00 68 68 11 60 00 68 C0 23 60 00 E8 AB FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0 66 8B 41 06 89 54 24 14 8D 68 FF 85 ED 7C 37 33 C0  }

condition:
		$a0 at entrypoint
}
	
	
rule Software_Compress_v1_2____BG_Software_Protect_Technologies
{
strings:
		$a0 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 FF 74 24 24 6A 40 FF 95 1A 0F 41 00 89 44 24 1C 61 C2 04 00 E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__ASProtect______Anorganix
{
strings:
		$a0 = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Thunderbolt_V0_02____deXep__forgot______Sign_By_fly
{
strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 E8 AA 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5D 68 00 FE 9F 07 53 E8 5D 00 00 00 EB FF 71 E8 C2 50 00 EB D6 5E F3 68 89 74 24 48 74 24 58 FF 8D 74 24 58 5E 83 C6 4C 75 F4 59 8D 71 E8 75 09 81 F6 EB FF 51 B9 01 00 83 EE FC 49 FF 71 C7 75 19 8B 74 24 00 00 81 36 50 56 8B 36 EB FF 77 C4 36 81 F6 EB 87 34 24 8B 8B 1C 24 83 EC FC EB 01 E8 83 EC FC E9 E7 00 00 00 5B EB FF F3 EB FF C3  }

condition:
		$a0 at entrypoint
}
	
	
rule CopyControl_v3_03
{
strings:
		$a0 = { CC 90 90 EB 0B 01 50 51 52 53 54 61 33 61 2D 35 CA D1 07 52 D1 A1 3C  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Spin_v0_4x
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_Delphi_Setup_Module
{
strings:
		$a0 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Trivial_25
{
strings:
		$a0 = { B4 4E FE C6 CD 21 B8 ?? 3D BA ?? 00 CD 21 93 B4 40 CD  }

condition:
		$a0 at entrypoint
}
	
	
rule Aluwain_v8_09
{
strings:
		$a0 = { 8B EC 1E E8 ?? ?? 9D 5E  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_Delphi_vx_x__Component_
{
strings:
		$a0 = { C3 E9 ?? ?? ?? FF 8D 40  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___v4_2_DLL
{
strings:
		$a0 = { 53 B8 ?? ?? ?? ?? 8B ?? ?? ?? 56 57 85 DB 55 75  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_2_rule__Watcom_C_C___DLL______Anorganix
{
strings:
		$a0 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 01 00 00 00 F1  }

condition:
		$a0 at entrypoint
}
	
	
rule BamBam_v0_01
{
strings:
		$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 FB ?? ?? 00 E8 6C FD FF FF B9 05 00 00 00 8B F3 BF FB ?? ?? 00 53 F3 A5 E8 8D 05 00 00 8B 3D 03 ?? ?? 00 A1 2B ?? ?? 00 66 8B 15 2F ?? ?? 00 B9 80 ?? ?? 00 2B CF 89 45 E8 89 0D 6B ?? ?? 00 66 89 55 EC 8B 41 3C 33 D2 03 C1 83 C4 10 66 8B 48 06 66 8B 50 14 81 E1 FF FF 00 00 8D 5C 02 18 8D 41 FF 85 C0 0F 8E 39 01 00 00 89 45 F0 C6 45 FF 00 8D 7D E8 8B F3 8A 0E 8A 17 8A C1 3A CA 75 1E 84 C0 74 16 8A 56 01 8A 4F 01 8A C2 3A D1 75 0E 83 C6 02 83 C7 02 84 C0 75 DC 33 C0 EB 05 1B C0 83 D8 FF 85 C0 75 04 C6 45 FF 01 8B 43 10 85 C0 0F 84 DD 00 00 00 8B 43 08 50 E8 D7 04 00 00 8A 4D FF 83 C4 04 84 C9 8B 4B 08 89 45 F8 C7 45 F4 00 00 00 00 74 61 8B 15 07 ?? ?? 00 8B 35 6B ?? ?? 00 8B 7B 0C 2B CA 03 F2 8B D1 03 F7 8B F8 C1 E9 02 F3 A5  }

condition:
		$a0 at entrypoint
}
	
	
rule ZipWorxSecureEXE_v2_5____ZipWORX_Technologies_LLC
{
strings:
		$a0 = { E9 B8 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 53 65 63 75 72 65 45 58 45 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 28 63 29 20 32 30  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_VIRUS_I_Worm_Hybris_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 EB 16 A8 54 00 00 47 41 42 4C 4B 43 47 43 00 00 00 00 00 00 52 49 53 00 FC 68 4C 70 40 00 FF 15  }

condition:
		$a0 at entrypoint
}
	
	
rule SimbiOZ_____Russian_PacK____Sign_By_fly
{
strings:
		$a0 = { 50 60 E8 00 00 00 00 5D 81 ED 07 10 40 00 68 80 0B 00 00 8D 85 1F 10 40 00 50 E8 84 0B 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_v1_18_Basic_rule__aPLib_____Ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83  }

condition:
		$a0 at entrypoint
}
	
	
rule UPack_Alt_Stub____Dwing
{
strings:
		$a0 = { 60 E8 09 00 00 00 C3 F6 00 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD  }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor_V1_4_5_1____CGSoftLabs_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 83 65 ?? 00 F3 EB 0C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B 48 18 89 ?? ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? 74 16 A1 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 03 48 14 89 4D ?? E9 ?? ?? ?? ?? C7 05  }

condition:
		$a0 at entrypoint
}
	
	
rule Petite_v2_1__2_
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 66 9C 60 50  }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor_v1_3____CGSoftLabs
{
strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 33 2E 2E B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 13 A1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 89 ?? ?? E9 ?? ?? 00 00 C7 05  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Virtualization_Suite_V3_049_V3_080____Thinstall_Company_____Sign_By_fly
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 2C 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB  }

condition:
		$a0 at entrypoint
}
	
	
rule CipherWall_Self_Extrator_Decryptor__GUI__v1_5
{
strings:
		$a0 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 F9 89 C7 6A 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF 5E 89 F7 B9 52 10 00 00 8A 07 47 2C E8 3C 01 77 F7 80 3F 0E 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4  }

condition:
		$a0 at entrypoint
}
	
	
rule VX__Tibs_Zhelatin__StormWorm__variant
{
strings:
		$a0 = { FF 74 24 1C 58 8D 80 ?? ?? 77 04 50 68 62 34 35 04 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_3_035____Jtit
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 C3 B9 08 00 00 00 E8 01 00 00 00 C3 33 C0 E8 E1 FF FF FF 13 C0 E2 F7 C3 33 C9 41 E8 D4 FF FF FF 13 C9 E8 CD FF FF FF 72 F2 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Danish_tiny
{
strings:
		$a0 = { 33 C9 B4 4E CD 21 73 02 FF ?? BA ?? 00 B8 ?? 3D CD 21  }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptor_2_0____Vaska
{
strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_20__LZMA_4_30_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 9C 0C 00 00 EB 0C 8B 85 98 0C 00 00 89 85 9C 0C 00 00 8D B5 C4 0C 00 00 8D 9D 82 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 2D 0C 00 00 89 85 94 0C 00 00 E8 59 01 00 00 EB 20 60 8B 85 9C 0C 00 00 FF B5 94 0C 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD A8 0C 00 00 00 74 0E 83 BD AC 0C 00 00 00 74 05 E8 F2 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 2D 0C 00 00 89 85 C0 0C 00 00 5B 60 FF B5 94 0C 00 00 56 FF B5 C0 0C 00 00 FF D3 61 8B B5 C0 0C 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 9C 0C 00 00 83 C0 04 89 85 BC 0C 00 00 EB 72 56 FF 95 25 0C 00 00 0B C0 75 05 E8 E6 02 00 00 85 C0 0F 84 AB 00 00 00 89 85 B8 0C 00 00 8B C6 EB 2E 8B 85 BC 0C 00 00 8B 00 50 FF B5 B8 0C 00 00 E8 2E 02 00 00 85 C0 0F 84 85 00 00 00 89 07 83 85 BC 0C 00 00 04 83 C7 04 8B 85 BC 0C 00 00 83 38 00 75 CD EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD 9C 0C 00 00 83 C0 04 89 85 BC 0C 00 00 80 3E 01 75 89 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 C0 0C 00 00 FF 95 31 0C 00 00 68 00 80 00 00 6A 00 FF B5 C0 0C 00 00 FF 95 31 0C 00 00 68 00 80 00 00 6A 00 FF B5 94 0C 00 00 FF 95 31 0C 00 00 E8 61 00 00 00 E8 5C 01 00 00 61 E9 ?? ?? ?? ?? 61 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__TravJack_883
{
strings:
		$a0 = { EB ?? 9C 9E 26 ?? ?? 51 04 ?? 7D ?? 00 ?? 2E ?? ?? ?? ?? 8C C8 8E C0 8E D8 80 ?? ?? ?? ?? 74 ?? 8A ?? ?? ?? BB ?? ?? 8A ?? 32 C2 88 ?? FE C2 43 81  }

condition:
		$a0 at entrypoint
}
	
	
rule FishPE_V1_0X____hellfish_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? C3 90 09 00 00 00 2C 00 00 00 ?? ?? ?? ?? C4 03 00 00 BC A0 00 00 00 40 01 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 00 00 00 00 8A 00 00 00 10 00 00 ?? ?? 00 00 ?? ?? ?? ?? 00 00 02 00 00 00 A0 00 00 18 01 00 00 ?? ?? ?? ?? 00 00 0C 00 00 00 B0 00 00 38 0A 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 C0 00 00 40 39 00 00 ?? ?? ?? ?? 00 00 08 00 00 00 00 01 00 C8 06 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule SimbiOZ_PolyCryptor_v_xx___Extranger
{
strings:
		$a0 = { 55 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Morphine_1_2______Anorganix
{
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 EB 08 E8 90 00 00 00 66 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 51 66 90 90 90 59 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90  }

condition:
		$a0 at entrypoint
}
	
	
rule Virogen_Crypt_v0_75
{
strings:
		$a0 = { 9C 55 E8 EC 00 00 00 87 D5 5D 60 87 D5 80 BD 15 27 40 00 01  }

condition:
		$a0 at entrypoint
}
	
	
rule CodeCrypt_v0_14b
{
strings:
		$a0 = { E9 C5 02 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_5_7____Obsidium_Software_____Sign_By_fly___20080521
{
strings:
		$a0 = { EB 01 ?? E8 ?? 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 ?? ?? ?? ?? EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 03 ?? ?? ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 01 ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Pack_v0_99
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 83 ED 06 80 BD E0 04 ?? ?? 01 0F 84 F2  }

condition:
		$a0 at entrypoint
}
	
	
rule mPack_0_0_3____DeltaAziz
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 33 C0 89 45 F0 B8 A8 76 00 10 E8 67 C4 FF FF 33 C0 55 68 C2 78 00 10 64 FF 30 64 89 20 8D 55 F0 33 C0 E8 93 C8 FF FF 8B 45 F0 E8 87 CB FF FF A3 08 A5 00 10 33 C0 55 68 A5 78 00 10 64 FF 30 64 89 20 A1 08 A5 00 10 E8 FA C9 FF FF 83 F8 FF 75 0A E8 88 B2 FF FF E9 1B 01 00 00 C7 05 14 A5 00 10 32 00 00 00 A1 08 A5 00 10 8B 15 14 A5 00 10 E8 C9 C9 FF FF BA 14 A5 00 10 A1 08 A5 00 10 B9 04 00 00 00 E8 C5 C9 FF FF 83 3D 14 A5 00 10 32 77 0A E8 47 B2 FF FF E9 DA 00 00 00 A1 08 A5 00 10 8B 15 14 A5 00 10 E8 92 C9 FF FF BA 18 A5  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Grazie_883
{
strings:
		$a0 = { 1E 0E 1F 50 06 BF 70 03 B4 1A BA 70 03 CD 21 B4 47 B2 00 BE 32 04 CD 21  }

condition:
		$a0 at entrypoint
}
	
	
rule PEEncrypt_v4_0b__JunkCode_
{
strings:
		$a0 = { 66 ?? ?? 00 66 83 ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Eddie_2100
{
strings:
		$a0 = { E8 ?? ?? 4F 4F 0E E8 ?? ?? 47 47 1E FF ?? ?? CB E8 ?? ?? 84 C0 ?? ?? 50 53 56 57 1E 06 B4 51 CD 21 8E C3 ?? ?? ?? ?? ?? ?? ?? 8B F2 B4 2F CD 21 AC  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Crypt32_v1_02
{
strings:
		$a0 = { E8 00 00 00 00 5B 83 ?? ?? EB ?? 52 4E 44 21  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__ACME__Clonewar_Mutant_
{
strings:
		$a0 = { FC AD 3D FF FF 74 20 E6 42 8A C4 E6 42 E4 61 0C 03 E6 61 AD B9 40 1F E2 FE  }

condition:
		$a0 at entrypoint
}
	
	
rule X_PEOR_v0_99b
{
strings:
		$a0 = { E8 00 00 00 00 5D 8B CD 81 ED 7A 29 40 00 89 AD 0F 6D 40 00  }
	$a1 = { E8 ?? ?? ?? ?? 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D 40  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PCShrink_0_71_beta
{
strings:
		$a0 = { 01 AD 54 3A 40 00 FF B5 50 3A 40 00 6A 40 FF 95 88 3A 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Borland_Delphi_3_0______Anorganix
{
strings:
		$a0 = { 55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90  }

condition:
		$a0 at entrypoint
}
	
	
rule kkrunchy_0_23_alpha____Ryd
{
strings:
		$a0 = { BD 08 ?? ?? 00 C7 45 00 ?? ?? ?? 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? 00 57 BE ?? ?? ?? 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10 8D 9D A0 08 00 00 E8 ?? 00 00 00 8B 45 10 EB 42 8D 9D A0 04 00 00 E8 ?? 00 00 00 49 49 78 40 8D 5D 20 74 03 83 C3 40 31 D2 42 E8 ?? 00 00 00 8D 0C 48 F6 C2 10 74 F3 41 91 8D 9D A0 08 00 00 E8 ?? 00 00 00 3D 00 08 00 00 83 D9 FF 83 F8 60 83 D9 FF 89 45 10 56 89 FE 29 C6 F3 A4 5E EB 90 BE ?? ?? ?? 00 BB ?? ?? ?? 00 55 46 AD 85 C0 74 ?? 97 56 FF 13 85 C0 74 16 95 AC 84 C0 75 FB 38 06 74 E8 78 ?? 56 55 FF 53 04 AB 85 C0  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_v1_18_Basic_DLL_rule__aPLib_____Ap0x
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v1_02b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43  }
	$a1 = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ASPack_v1_02a
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 3E D9 43 ?? B8 38 ?? ?? ?? 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 ?? ?? 75 15 FE 85 01 DE 43 ?? E8 1D ?? ?? ?? E8 79 02 ?? ?? E8 12 03 ?? ?? 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v2_1
{
strings:
		$a0 = { 60 E8 72 05 00 00 EB 33 87 DB 90 00  }

condition:
		$a0 at entrypoint
}
	
	
rule ACProtect_V2_0____risco
{
strings:
		$a0 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? C3 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Alex_Protector_1_0_beta_2_by_Alex
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B 44 24 0C EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 83 80 B8 00 00 00 02 33 C0 EB 01 E9 C3 58 83 C4 04 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 EB 01 E9 FF FF 60 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 0F 31 8B D8 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 8B CA EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 0F 31 2B C3 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 1B D1 0F 31 03 C3 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 13 D1 0F 31 2B C3 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 EB 05 68 F0 0F C7 C8 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 1B D1 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 85  }

condition:
		$a0 at entrypoint
}
	
	
rule Packanoid_V1_0____Arkanoid
{
strings:
		$a0 = { BF ?? ?? ?? ?? BE ?? ?? ?? ?? E8 9D 00 00 00 B8 ?? ?? ?? ?? 8B 30 8B 78 04 BB ?? ?? ?? ?? 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_53b3
{
strings:
		$a0 = { 55 8B EC 6A FF 68 D8 ?? ?? ?? 68 14 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_v1_3_0_0____Obsidium_Software
{
strings:
		$a0 = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B 50 EB 03 8A 0B 93 33 C0 EB 02 28 B9 8B 00 EB 01 04 C3 EB 04 65 B3 54 0A E9 FA 00 00 00 EB 01 A2 E8 D5 FF FF FF EB 02 2B 49 EB 03 7C 3E 76 58 EB 04 B8 94 92 56 EB 01 72 64 67 8F 06 00 00 EB 02 23 72 83 C4 04 EB 02 A9 CB E8 47 26 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule WARNING____TROJAN____ADinjector
{
strings:
		$a0 = { 90 61 BE 00 20 44 00 8D BE 00 F0 FB FF C7 87 9C E0 04 00 6A F0 8A 5E 57 83 CD FF EB 0E  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_xx__CopyMem_II_
{
strings:
		$a0 = { 6A ?? 8B B5 ?? ?? ?? ?? C1 E6 04 8B 85 ?? ?? ?? ?? 25 07 ?? ?? 80 79 05 48 83 C8 F8 40 33 C9 8A 88 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 81 E2 07 ?? ?? 80 79 05 4A 83 CA F8 42 33 C0 8A 82  }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtect_V2_X_DLL____Alexey_Solodovnikov
{
strings:
		$a0 = { 60 E8 03 00 00 00 E9 ?? ?? 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ?? ?? ?? ?? 03 DD  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_1_3_3_3____Obsidium_Software
{
strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 27  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Crypt32__Console_v1_0__v1_01__v1_02_
{
strings:
		$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB  }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor_V1_1____CGSoftLabs_____Sign_By_fly
{
strings:
		$a0 = { E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? 12 00 00 E9 ?? 0C 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Alloy_4_x____PGWare_LLC
{
strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95 A8 33 40 00 0B C0 0F 84 F6 01 00 00 89 85 2E 33 40 00 83 BD E8 32 40 00 01 74 0D 83 BD E4 32 40 00 01 74 2A 8B F8 EB 3E 68  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_19__LZMA_4_30_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 01 00 00 EB 20 60 8B 85 49 0B 00 00 FF B5 41 0B 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD 55 0B 00 00 00 74 0E 83 BD 59 0B 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 DA 0A 00 00 89 85 69 0B 00 00 5B 60 FF B5 41 0B 00 00 56 FF B5 69 0B 00 00 FF D3 61 8B B5 69 0B 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 E9 98 00 00 00 56 FF 95 D2 0A 00 00 89 85 61 0B 00 00 85 C0 0F 84 C8 00 00 00 8B C6 EB 5F 8B 85 65 0B 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 65 0B 00 00 C7 00 20 20 20 00 EB 06 FF B5 65 0B 00 00 FF B5 61 0B 00 00 FF 95 D6 0A 00 00 85 C0 0F 84 87 00 00 00 89 07 83 C7 04 8B 85 65 0B 00 00 EB 01 40 80 38 00 75 FA 40 89 85 65 0B 00 00 66 81 78 02 00 80 74 A1 80 38 00 75 9C EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 80 3E 01 0F 85 5F FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 69 0B 00 00 FF 95 DE 0A 00 00 68 00 40 00 00 68 00 20 0C 00 FF B5 41 0B 00 00 FF 95 DE 0A 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_V2_7X____Jitit
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Inno_Setup_Module_v1_09a
{
strings:
		$a0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33 C0  }

condition:
		$a0 at entrypoint
}
	
	
rule Sentinel_SuperPro__Automatic_Protection__v6_4_0____Safenet
{
strings:
		$a0 = { 68 ?? ?? ?? ?? 6A 01 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C9 3D B7 00 00 00 A1 ?? ?? ?? ?? 0F 94 C1 85 C0 89 0D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 15  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Intro_v1_0
{
strings:
		$a0 = { 8B 04 24 9C 60 E8 ?? ?? ?? ?? 5D 81 ED 0A 45 40 ?? 80 BD 67 44 40 ?? ?? 0F 85 48  }

condition:
		$a0 at entrypoint
}
	
	
rule Pksmart_1_0b
{
strings:
		$a0 = { BA ?? ?? 8C C8 8B C8 03 C2 81 ?? ?? ?? 51 B9 ?? ?? 51 1E 8C D3  }

condition:
		$a0 at entrypoint
}
	
	
rule RatPacker__Glue__stub
{
strings:
		$a0 = { 40 20 FF ?? ?? ?? ?? ?? ?? ?? ?? BE ?? 60 40 ?? 8D BE ?? B0 FF FF  }
	$a1 = { 40 20 FF 00 00 00 00 00 00 00 ?? BE 00 60 40 00 8D BE 00 B0 FF FF  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule R_SC_s_Process_Patcher_v1_5_1
{
strings:
		$a0 = { 68 00 20 40 00 E8 C3 01 00 00 80 38 00 74 0D 66 81 78 FE 22 20 75 02 EB 03 40 EB EE 8B F8 B8 04 60 40 00 68 C4 20 40 00 68 D4 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 9F 01 00 00 85 C0 0F 84 39 01 00 00 BE 00 60 40 00 8B 06 A3 28 21 40 00 83 C6 40 83 7E FC 00 0F 84 8F 00 00 00 8B 3E 83 C6 04 85 FF 0F 84 E5 00 00 00 81 FF 72 21 73 63 74 7A 0F B7 1E 8B CF 8D 7E 02 C7 05 24 21 40 00 00 00 00 00 83 05 24 21 40 00 01 50 A1 28 21 40 00 39 05 24 21 40 00 58 0F 84 D8 00 00 00 60 6A 00 53 68 2C 21 40 00 51 FF 35 C4 20 40 00 E8 0A 01 00 00 61 60 FC BE 2C 21 40 00 8B CB F3 A6 61 75 C2 03 FB 60 E8 3E 00 00 00 6A 00 53 57 51 FF 35 C4 20 40 00 E8 FB 00 00 00 85 C0 0F 84 A2 00 00 00 61 03 FB 8B F7 E9 71 FF FF FF 60 FF 35 C8 20 40 00 E8 CB 00 00 00 61 C7 05  }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtect_v1_23_RC1
{
strings:
		$a0 = { 68 01 ?? ?? 00 E8 01 00 00 00 C3 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_0_4____Obsidium_Software
{
strings:
		$a0 = { EB 02 ?? ?? E8 ?? 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule MPRESS_V2_00_V2_0X____MATCODE_Software_____Sign_By_fly___20090423
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 05 ?? ?? ?? ?? 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 88 04 31 75 F6  }

condition:
		$a0 at entrypoint
}
	
	
rule Vcasm_Protector_V1_X____vcasm
{
strings:
		$a0 = { EB ?? 5B 56 50 72 6F 74 65 63 74 5D  }

condition:
		$a0 at entrypoint
}
	
	
rule EEXE_Version_1_12
{
strings:
		$a0 = { B4 30 CD 21 3C 03 73 ?? BA 1F 00 0E 1F B4 09 CD 21 B8 FF 4C CD 21  }

condition:
		$a0 at entrypoint
}
	
	
rule N_Joy_1_2____NEX
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 A4 32 40 00 E8 E8 F1 FF FF 6A 00 68 54 2A 40 00 6A 0A 6A 00 E8 A8 F2 FF FF E8 C7 EA FF FF 8D 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule The_Best_Cryptor____FsK_____Sign_By_fly
{
strings:
		$a0 = { EB 06 56 52 55 4C 5A 00 90 90 90 90 90 90 90 90  }

condition:
		$a0 at entrypoint
}
	
	
rule PEiD_Bundle_v1_02___v1_04_____BoB___BobSoft
{
strings:
		$a0 = { 60 E8 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44  }

condition:
		$a0 at entrypoint
}
	
	
rule Enigma_Protector_v1_12_LITE
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31  }

condition:
		$a0 at entrypoint
}
	
	
rule Crinkler_V0_1_V0_2____Rune_L_H_Stubbe_and_Aske_Simon_Christensen_____Sign_By_fly
{
strings:
		$a0 = { B9 ?? ?? ?? ?? 01 C0 68 ?? ?? ?? ?? 6A 00 58 50 6A 00 5F 48 5D BB 03 00 00 00 BE ?? ?? ?? ?? E9  }

condition:
		$a0 at entrypoint
}
	
	
rule GameGuard___nProtect
{
strings:
		$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE ?? ?? ?? ?? 31 FF 74 06 61 E9 4A 4D 50 30 8D BE ?? ?? ?? ?? 31 C9 74 06 61 E9 4A 4D 50 30 B8 7D 00 00 00 39 C2 B8 4C 00 00 00 F7 D0 75 3F 64 A1 30 00 00 00 85 C0 78 23 8B 40 0C 8B 40 0C C7 40 20 00 10 00 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 85 C0 75 16 E9 12 00 00 00 31 C0 64 A0 20 00 00 00 85 C0 75 05 E9 01 00 00 00 61 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Embedded_V2_545____Jitit_____Sign_By_fly
{
strings:
		$a0 = { E8 F2 FF FF FF 50 68 ?? ?? ?? ?? 68 40 1B 00 00 E8 42 FF FF FF E9 9D FF FF FF 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule GameGuard_v2006_5_x_x____dll_____sign_by_hot_UNP
{
strings:
		$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 BA 4C 00 00 00 80 7C 24 08 01 0F 85 ?? 01 00 00 60 BE 00  }

condition:
		$a0 at entrypoint
}
	
	
rule iLUCRYPT_v4_018_rule__exe_
{
strings:
		$a0 = { 8B EC FA C7 ?? ?? ?? ?? 4C 4C C3 FB BF ?? ?? B8 ?? ?? 2E ?? ?? D1 C8 4F 81  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_3_9____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 28 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 CF 27 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Nullsoft_Install_System_v1_xx
{
strings:
		$a0 = { 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00 56 56 56 89 75 E4 E8 C1 C9 FF FF 8B 1D 68 70 40 00 83 C4 0C 89 45 E8 89 75 F0 6A 02 56 6A FC 57 FF D3 89 45 FC 8D 45 F8 56 50 8D 45 E4 6A 04 50 57 FF 15 48 70 40 00 85 C0 75 07 BB 7C 9E 40 00 EB 7A 56 56 56 57 FF D3 39 75 FC 7E 62 BF 74 A2 40 00 B8 00 10 00 00 39 45 FC 7F 03 8B 45 FC 8D 4D F8 56 51 50 57 FF 75 EC FF 15 48 70 40 00 85 C0 74 5A FF 75 F8 57 FF 75 E8 E8 4D C9 FF FF 89 45 E8 8B 45 F8 29 45 FC 83 C4 0C 39 75 F4 75 11 57 E8 D3 F9 FF FF 85 C0 59 74 06 8B 45 F0 89 45 F4 8B 45 F8 01 45 F0 39 75 FC  }
	$a1 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 74 05 56 FF D7 8B F0 89 74 24 14 80 3E 20 75 07 56 FF D7 8B F0 EB F4 80 3E 2F 75  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Obsidium_V1_3_5_0____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 20 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 ?? ?? ?? ?? EB 01 ?? EB 02 ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule PEiD_Bundle_V1_01____BoB___BobSoft
{
strings:
		$a0 = { 60 E8 23 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v1_07b__DLL_
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Igor
{
strings:
		$a0 = { 1E B8 CD 7B CD 21 81 FB CD 7B 75 03 E9 87 00 33 DB 0E 1F 8C  }

condition:
		$a0 at entrypoint
}
	
	
rule Warning__may_be_SimbyOZ_polycryptor_by_3xpl01t_ver_2_xx__25_03_2007_22_00_
{
strings:
		$a0 = { 57 57 8D 7C 24 04 50 B8 00 D0 17 13 AB 58 5F C3 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule MicroJoiner_1_5____coban2k
{
strings:
		$a0 = { BF 05 10 40 00 83 EC 30 8B EC E8 C8 FF FF FF E8 C3 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule eXpressor_v1_1____CGSoftLabs
{
strings:
		$a0 = { E9 15 13 00 00 E9 F0 12 00 00 E9 58 12 00 00 E9 AF 0C 00 00 E9 AE 02 00 00 E9 B4 0B 00 00 E9 E0 0C 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule XCR_v0_13
{
strings:
		$a0 = { 93 71 08 ?? ?? ?? ?? ?? ?? ?? ?? 8B D8 78 E2 ?? ?? ?? ?? 9C 33 C3 ?? ?? ?? ?? 60 79 CE ?? ?? ?? ?? E8 01 ?? ?? ?? ?? 83 C4 04 E8 AB FF FF FF ?? ?? ?? ?? 2B E8 ?? ?? ?? ?? 03 C5 FF 30 ?? ?? ?? ?? C6 ?? EB  }

condition:
		$a0 at entrypoint
}
	
	
rule XCR_v0_12
{
strings:
		$a0 = { 60 9C E8 ?? ?? ?? ?? 8B DD 5D 81 ED ?? ?? ?? ?? 89 9D  }

condition:
		$a0 at entrypoint
}
	
	
rule ChSfx__small__v1_1
{
strings:
		$a0 = { BA ?? ?? E8 ?? ?? 8B EC 83 EC ?? 8C C8 BB ?? ?? B1 ?? D3 EB 03 C3 8E D8 05 ?? ?? 89  }

condition:
		$a0 at entrypoint
}
	
	
rule Symantec_Visual_Cafe_v3_0
{
strings:
		$a0 = { 64 8B 05 ?? ?? ?? ?? 55 8B EC 6A FF 68 ?? ?? 40 ?? 68 ?? ?? 40 ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 08 50 53 56 57 89 65 E8 C7 45 FC  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_2_4x___2_5x____Jitit_Software
{
strings:
		$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? BD ?? ?? ?? ?? 03 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule ExeBundle_v3_0__standard_loader_
{
strings:
		$a0 = { 00 00 00 00 60 BE 00 B0 42 00 8D BE 00 60 FD FF C7 87 B0 E4 02 00 31 3C 4B DF 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB  }

condition:
		$a0 at entrypoint
}
	
	
rule VIRUS___I_Worm_KLEZ
{
strings:
		$a0 = { 55 8B EC 6A FF 68 40 D2 40 ?? 68 04 AC 40 ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 BC D0  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_Shit_v0_1____500mhz
{
strings:
		$a0 = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 01 ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79  }
	$a1 = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79  }
	$a2 = { E8 ?? ?? ?? ?? 5E 83 C6 ?? AD 89 C7 AD 89 C1 AD 30 07 47 E2 ?? AD FF E0 C3  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule BeRoEXEPacker_v1_00_DLL_rule__LZBRR_____BeRo___Farbrausch
{
strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 ?? ?? ?? ?? 73 F6 33 C9 E8 ?? ?? ?? ?? 73 1C 33 C0 E8 ?? ?? ?? ?? 73 23 B3 02 41 B0 10  }

condition:
		$a0 at entrypoint
}
	
	
rule PassEXE_v2_0
{
strings:
		$a0 = { 06 1E 0E 0E 07 1F BE ?? ?? B9 ?? ?? 87 14 81 ?? ?? ?? EB ?? C7 ?? ?? ?? 84 00 87 ?? ?? ?? FB 1F 58 4A  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_Delphi_v2_0
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0A ?? ?? ?? B8 ?? ?? ?? ?? C3  }

condition:
		$a0 at entrypoint
}
	
	
rule nPack_v1_1_250_Beta____NEOx
{
strings:
		$a0 = { 83 3D 04 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 2E ?? ?? ?? 2B 05 08 ?? ?? ?? A3 00 ?? ?? ?? E8 9C 00 00 00 E8 04 02 00 00 E8 FB 06 00 00 E8 1B 06 00 00 A1 00 ?? ?? ?? C7 05 04 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00  }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor_2_2_6__minimum_protection_
{
strings:
		$a0 = { 50 68 ?? ?? ?? ?? 58 81 E0 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 0C 24 59 E8 ?? ?? ?? 00 89 45 F8 E9 ?? ?? ?? ?? 0F 83 ?? ?? ?? 00 E9 ?? ?? ?? ?? 87 14 24 5A 57 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 58 81 C0 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? 81 C8 ?? ?? ?? ?? 81 E0 ?? ?? ?? ?? E9 ?? ?? ?? 00 C3 E9 ?? ?? ?? ?? C3 BF ?? ?? ?? ?? 81 CB ?? ?? ?? ?? BA ?? ?? ?? ?? 52 E9 ?? ?? ?? 00 E8 ?? ?? ?? 00 E9 ?? ?? ?? 00 E9 ?? ?? ?? ?? 87 34 24 5E 66 8B 00 66 25 ?? ?? E9 ?? ?? ?? ?? 8B CD 87 0C 24 8B EC 51 89 EC 5D 8B 05 ?? ?? ?? ?? 09 C0 E9 ?? ?? ?? ?? 59 81 C1 ?? ?? ?? ?? C1 C1 ?? 23 0D ?? ?? ?? ?? 81 F9 ?? ?? ?? ?? E9 ?? ?? ?? ?? C3 E9 ?? ?? ?? 00 13 D0 0B F9 E9 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 8B 64 24 08 31 C0 64 8F 05 00 00 00 00 5A E9 ?? ?? ?? ?? 3C A4 0F 85 ?? ?? ?? 00 8B 45 FC 66 81 38 ?? ?? 0F 84 05 00 00 00 E9 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? E9 ?? ?? ?? ?? 87 3C 24 5F 31 DB 31 C9 31 D2 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 89 45 FC 33 C0 89 45 F4 83 7D FC 00 E9 ?? ?? ?? ?? 53 52 8B D1 87 14 24 81 C0 ?? ?? ?? ?? 0F 88 ?? ?? ?? ?? 3B CB  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_5_3____Obsidium_Software_____Sign_By_fly___20080120
{
strings:
		$a0 = { EB 02 ?? ?? E8 2B 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_v0_31_beta____Dwing
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_2_93___3_00_rule__LZMA_____Markus_Oberhumer__Laszlo_Molnar___John_Reiser
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 03 00 02 00 90 90 90 90 90  }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor_Standard_V1_7_0_1____CGSoftLabs_____Sign_By_fly___20090603
{
strings:
		$a0 = { 55 8B EC 81 EC ?? 02 00 00 53 56 57 83 A5 A0 FD FF FF 00 F3 EB 0C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 40 04 25 00 00 00 80 74 61 83 7D 0C 01 75 2A 8B 45 08 A3 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 75 19 6A 04 68 00 10 00 00 68 20 03 00 00 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 7D 0C 00 75 13 83 ?? ?? ?? ?? ?? ?? 74 0A E9 66 0A 00 00 E9 61 0A 00 00 83 ?? ?? ?? ?? ?? ?? 74 05 E9 BE 09 00 00 C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 78 60 00 75 1C 6A 10 6A 00 E8 AD 17 00 00 59 50 6A 01 E8 A4 17 00 00 59 50 6A 00 FF 15 ?? ?? ?? ?? E8 98 0A 00 00 A3 ?? ?? ?? ?? 6A 04 68 00 10 00 00 68 80 00 00 00 6A 00 FF 15 ?? ?? ?? ?? 89 85 D0 FD FF FF 68 04 01 00 00 8D 85 D8 FD FF FF 50 FF ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8D 84 05 D7 FD FF FF 89 85 A4 FD FF FF 8B 85 A4 FD FF FF 0F BE 00 83 F8 5C  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Virtualization_Suite_V3_10X_3_X____Thinstall_Company_____Sign_By_fly___20090514
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 2C FF FF FF E9 90 FF FF FF CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9  }

condition:
		$a0 at entrypoint
}
	
	
rule T_PACK_v0_5c__m1
{
strings:
		$a0 = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 8E FE  }

condition:
		$a0 at entrypoint
}
	
	
rule T_PACK_v0_5c__m2
{
strings:
		$a0 = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 CE FD  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_PESHiELD_2_x_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04  }

condition:
		$a0 at entrypoint
}
	
	
rule CreateInstall_Stub_vx_x
{
strings:
		$a0 = { 55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 18 61 40 00 68 00 70 40 00 89 45 08 FF 15 14 61 40 00 85 C0 74 27 6A 00 A1 00 20 40 00 50 FF 15 3C 61 40 00 8B F0 6A 06 56 FF 15 38 61 40 00 6A 03 56 FF 15 38 61 40 00 E9 36 03 00 00 68 02 7F 00 00 33 F6 56 BF 00 30 00 00 FF 15 20 61 40 00 50 FF 15 2C 61 40 00 6A 04 57 68 00 FF 01 00 56 FF 15 CC 60 40 00 6A 04 A3 CC 35 40 00 57 68 00 0F 01 00 56 FF 15 CC 60 40 00 68 00 01 00 00 BE B0 3F 40 00 56 A3 C4 30 40 00 FF 75 08 FF 15 10 61 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v2_0
{
strings:
		$a0 = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75  }

condition:
		$a0 at entrypoint
}
	
	
rule Metrowerks_CodeWarrior__DLL__v2_0
{
strings:
		$a0 = { 55 89 E5 53 56 57 8B 75 0C 8B 5D 10 83 FE 01 74 05 83 FE 02 75 12 53 56 FF 75 08 E8 6E FF FF FF 09 C0 75 04 31 C0 EB 21 53 56 FF 75 08 E8 ?? ?? ?? ?? 89 C7 09 F6 74 05 83 FE 03 75 0A 53 56 FF 75 08 E8 47 FF FF FF 89 F8 8D 65 F4 5F 5E 5B 5D C2 0C 00 C9  }

condition:
		$a0 at entrypoint
}
	
	
rule ID_Application_Protector_V1_2____ID_Security_Suite_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F2 0B 47 00 B9 19 22 47 00 81 E9 EA 0E 47 00 89 EA 81 C2 EA 0E 47 00 8D 3A 89 FE 31 C0 E9 D3 02 00 00 CC CC CC CC E9 CA 02 00 00 43 3A 5C 57 69 6E 64 6F 77 73 5C 53 6F 66 74 57 61 72 65 50 72 6F 74 65 63 74 6F 72 5C  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_Alternative_stub
{
strings:
		$a0 = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v1_03b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43  }

condition:
		$a0 at entrypoint
}
	
	
rule MinGW_v3_2_x__Dll_WinMain_
{
strings:
		$a0 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 76 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00 00 00 EB EB 8D B4 26 00 00 00 00 85 C0 75 D0 E8 47 00 00 00 EB C9 90 8D 74 26 00 C7 04 24 80 00 00 00 E8 A4 05 00 00 A3 00 30 00 10 85 C0 74 1A C7 00 00 00 00 00 A3 10 30 00 10 E8 1B 02 00 00 E8 A6 01 00 00 E9 75 FF FF FF E8 6C 05 00 00 C7 00 0C 00 00 00 31 C0 EB 98 89 F6 55 89 E5 83 EC 08 89 5D FC 8B 15 00 30 00 10 85 D2 74 29 8B 1D 10 30 00 10 83 EB 04 39 D3 72 0D 8B 03 85 C0 75 2A 83 EB 04 39 D3 73 F3 89 14 24 E8 1B 05 00 00 31 C0 A3 00 30 00 10 C7 04 24 00 00 00 00 E8 F8 04 00 00 8B 5D FC 89 EC 5D C3  }

condition:
		$a0 at entrypoint
}
	
	
rule _PIRIT_v1_5
{
strings:
		$a0 = { B4 4D CD 21 E8 ?? ?? FD E8 ?? ?? B4 51 CD 21  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_19_Dll__LZMA_4_30_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 C7 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 01 00 00 EB 20 60 8B 85 49 0B 00 00 FF B5 41 0B 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD 55 0B 00 00 00 74 0E 83 BD 59 0B 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 DA 0A 00 00 89 85 69 0B 00 00 5B 60 FF B5 41 0B 00 00 56 FF B5 69 0B 00 00 FF D3 61 8B B5 69 0B 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 E9 98 00 00 00 56 FF 95 D2 0A 00 00 89 85 61 0B 00 00 85 C0 0F 84 C8 00 00 00 8B C6 EB 5F 8B 85 65 0B 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 65 0B 00 00 C7 00 20 20 20 00 EB 06 FF B5 65 0B 00 00 FF B5 61 0B 00 00 FF 95 D6 0A 00 00 85 C0 0F 84 87 00 00 00 89 07 83 C7 04 8B 85 65 0B 00 00 EB 01 40 80 38 00 75 FA 40 89 85 65 0B 00 00 66 81 78 02 00 80 74 A1 80 38 00 75 9C EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 80 3E 01 0F 85 5F FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 69 0B 00 00 FF 95 DE 0A 00 00 68 00 40 00 00 68 00 20 0C 00 FF B5 41 0B 00 00 FF 95 DE 0A 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_33__Eng_____dulek_xt
{
strings:
		$a0 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D  }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoiner_Small__build_033_____GlOFF
{
strings:
		$a0 = { 50 66 33 C3 66 8B C1 58 E8 AC FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Nullsoft_PiMP_Stub_v1_x
{
strings:
		$a0 = { 83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05 E8 03 00 00 BE ?? ?? ?? 00 89 44 24 10 B3 20 FF 15 28 ?? 40 00 68 00 04 00 00 FF 15 ?? ?? 40 00 50 56 FF 15 ?? ?? 40 00 80 3D ?? ?? ?? 00 22 75 08 80 C3 02 BE ?? ?? ?? 00 8A 06 8B 3D ?? ?? 40 00 84 C0 74 ?? 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 74 05 56 FF D7 8B F0 89 74 24 14 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 3E 2F  }

condition:
		$a0 at entrypoint
}
	
	
rule PC_Shrinker_v0_20
{
strings:
		$a0 = { E8 E8 01 ?? ?? 60 01 AD B3 27 40 ?? 68  }

condition:
		$a0 at entrypoint
}
	
	
rule PC_Shrinker_v0_29
{
strings:
		$a0 = { BD ?? ?? ?? ?? 01 AD 55 39 40 ?? 8D B5 35 39 40  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Involuntary_1349
{
strings:
		$a0 = { BA ?? ?? B9 ?? ?? 8C DD ?? 8C C8 ?? 8E D8 8E C0 33 F6 8B FE FC ?? ?? AD ?? 33 C2 AB  }

condition:
		$a0 at entrypoint
}
	
	
rule EP_v1_0
{
strings:
		$a0 = { 50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC 86 C4 AC AA 86 C4 AA E2 F6 00 B8 40 00 03 00 3C 40 D2 33 8B 66 14 50 70 8B 8D 34 02 44 8B 18 10 48 70 03 BA 0C ?? ?? ?? ?? C0 33 FE 8B 30 AC 30 D0 C1 F0 10 C2 D0 30 F0 30 C2 C1 AA 10 42 42 CA C1 E2 04 5F E9 5E B1 C0 30 ?? 68 ?? ?? F3 00 C3 AA  }

condition:
		$a0 at entrypoint
}
	
	
rule Sentinel_Keys_Shell_Client_Library__V1_2_1_1____SafeNet_Inc______Sign_By_fly___20090524
{
strings:
		$a0 = { 55 8B EC A1 ?? ?? ?? ?? 53 56 57 85 C0 0F 85 A3 18 00 00 A1 ?? ?? ?? ?? 33 FF BB 01 00 00 00 3B C7 89 1D ?? ?? ?? ?? 0F 85 6C 07 00 00 75 03 74 01 ?? 83 EC 08 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 81 7C 24 3C 7C 03 7D 01 E8 9B 83 FF FF 7E 03 7F 01 ?? 89 1D ?? ?? ?? ?? 72 03 73 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 7C 24 28 75 03 74 01 A1 ?? ?? ?? ?? 25 07 00 00 80 79 05 48 83 C8 F8 40 A3 ?? ?? ?? ?? 7C 03 7D 01 ?? 39 3D ?? ?? ?? ?? 74 17 75 03 74 01 ?? 8B 0D ?? ?? ?? ?? A1 ?? ?? ?? ?? 2B C1 A3 ?? ?? ?? ?? 75 03 74 01 ?? FF 15  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_v0_10___v0_12_Beta____Dwing
{
strings:
		$a0 = { BE 48 01 ?? ?? ?? ?? ?? 95 A5 33 C0  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Armor_0_46____Hying
{
strings:
		$a0 = { E8 AA 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 5C ?? ?? 00 6F ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41  }
	$a1 = { E8 AA 00 00 00 2D ?? ?? ?? 00 00 00 00 00 00 00 00 3D  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ASPack_v1_08_01
{
strings:
		$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 ?? BB 10 ?? 44 ?? 03 DD 2B 9D  }
	$a1 = { 60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9  }
	$a2 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 00 BB 10 ?? 44 00 03 DD 2B 9D  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule ASPack_v1_08_02
{
strings:
		$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 00 BB 10 ?? 44 00 03 DD 2B 9D 72  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v1_08_03
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v1_08_04
{
strings:
		$a0 = { 60 E8 41 06 00 00 EB 41  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__PE_Protect_0_9______Anorganix
{
strings:
		$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Software_Compress_v1_4_LITE____BG_Software_Protect_Technologies
{
strings:
		$a0 = { E8 00 00 00 00 81 2C 24 AA 1A 41 00 5D E8 00 00 00 00 83 2C 24 6E 8B 85 5D 1A 41 00 29 04 24 8B 04 24 89 85 5D 1A 41 00 58 8B 85 5D 1A 41 00 8B 50 3C 03 D0 8B 92 80 00 00 00 03 D0 8B 4A 58 89 8D 49 1A 41 00 8B 4A 5C 89 8D 4D 1A 41 00 8B 4A 60 89 8D 55 1A 41 00 8B 4A 64 89 8D 51 1A 41 00 8B 4A 74 89 8D 59 1A 41 00 68 00 20 00 00 E8 D2 00 00 00 50 8D 8D 00 1C 41 00 50 51 E8 1B 00 00 00 83 C4 08 58 8D 78 74 8D B5 49 1A 41 00 B9 18 00 00 00 F3 A4 05 A4 00 00 00 50 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 FF 74 24 24 6A 40 FF 95 4D 1A 41 00 89 44 24 1C 61 C2 04  }

condition:
		$a0 at entrypoint
}
	
	
rule EPW_v1_30
{
strings:
		$a0 = { 06 57 1E 56 55 52 51 53 50 2E 8C 06 08 00 8C C0 83 C0 10 2E  }

condition:
		$a0 at entrypoint
}
	
	
rule ExeTools_COM2EXE
{
strings:
		$a0 = { E8 ?? ?? 5D 83 ED ?? 8C DA 2E 89 96 ?? ?? 83 C2 ?? 8E DA 8E C2 2E 01 96 ?? ?? 60  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Eddie_2000
{
strings:
		$a0 = { E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E 8B FE 33 C0 50 8E D8 C5 ?? ?? ?? B4 30 CD 21  }

condition:
		$a0 at entrypoint
}
	
	
rule Enigma_Protector_V1_0X____Sukhov_Vladimir_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ?? ?? 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 83 C4 04 EB 02 ?? ?? 60 E8 24 00 00 00 00 00 ?? EB 02 ?? ?? 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 ?? ?? 89 C4 61 EB 2E ?? ?? ?? ?? ?? ?? ?? EB 01 ?? 31 C0 EB 01 ?? 64 FF 30 EB 01 ?? 64 89 20 EB 02 ?? ?? 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 ?? 58 61 EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule CodeCrypt_v0_15b
{
strings:
		$a0 = { E9 31 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F  }

condition:
		$a0 at entrypoint
}
	
	
rule Securom7____Sony_DADC_____Sign_By_fly
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 8B ?? ?? ?? ?? 0A ?? ?? ?? ?? ?? ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule USERNAME_v3_00
{
strings:
		$a0 = { FB 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 8C C8 2B C1 8B C8 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 33 C0 8E D8 06 0E 07 FC 33 F6  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Embedded_V2_501____Jitit_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D A8 1A 00 00 B9 6D 1A 00 00 BA 21 1B 00 00 BE 00 10 00 00 BF C0 53 00 00 BD F0 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? 81 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10  }

condition:
		$a0 at entrypoint
}
	
	
rule Dr_Web_Virus_Finding_Engine____InSoft_EDV_Systeme
{
strings:
		$a0 = { B8 01 00 00 00 C2 0C 00 8D 80 00 00 00 00 8B D2 8B ?? 24 04  }

condition:
		$a0 at entrypoint
}
	
	
rule WebCops_rule__DLL_____LINK_Data_Security
{
strings:
		$a0 = { A8 BE 58 DC D6 CC C4 63 4A 0F E0 02 BB CE F3 5C 50 23 FB 62 E7 3D 2B  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Slowload
{
strings:
		$a0 = { 03 D6 B4 40 CD 21 B8 02 42 33 D2 33 C9 CD 21 8B D6 B9 78 01  }

condition:
		$a0 at entrypoint
}
	
	
rule Themida_WinLicense_V1_0_X_V1_7_X_DLL____Oreans_Technologies_____Sign_By_fly
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? ?? ?? ?? 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 ?? 89 48 01 61 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_V0_36____Dwing
{
strings:
		$a0 = { 0B 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 18 10 00 00 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 02 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 14 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 FF 76 08 FF 76 0C BE 1C 01  }
	$a1 = { BE ?? ?? ?? ?? FF 36 E9 C3 00 00 00  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Obsidium_V1_3_1_1____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 02 ?? ?? E8 27 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 22 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 03 ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03  }

condition:
		$a0 at entrypoint
}
	
	
rule PEncrypt_v1_0
{
strings:
		$a0 = { 60 9C BE 00 10 40 00 8B FE B9 28 03 00 00 BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE_v1_12__v1_15__v1_20__1_
{
strings:
		$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 73 ?? 2D ?? ?? FA 8E D0 FB 2D ?? ?? 8E C0 50 B9 ?? ?? 33 FF 57 BE ?? ?? FC F3 A5 CB B4 09 BA ?? ?? CD 21 CD 20  }

condition:
		$a0 at entrypoint
}
	
	
rule PENinja_modified
{
strings:
		$a0 = { 5D 8B C5 81 ED B2 2C 40 00 2B 85 94 3E 40 00 2D 71 02 00 00 89 85 98 3E 40 00 0F B6 B5 9C 3E 40 00 8B FD  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___5_0___6_0_
{
strings:
		$a0 = { 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB  }

condition:
		$a0 at entrypoint
}
	
	
rule Ady_s_Glue_1_10
{
strings:
		$a0 = { 2E ?? ?? ?? ?? 0E 1F BF ?? ?? 33 DB 33 C0 AC  }

condition:
		$a0 at entrypoint
}
	
	
rule PEncrypt_v3_1
{
strings:
		$a0 = { E9 ?? ?? ?? 00 F0 0F C6  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Crypter
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D EB 26  }

condition:
		$a0 at entrypoint
}
	
	
rule Simple_UPX_Cryptor_v30_4_2005_rule__multi_layer_encryption______MANtiCORE
{
strings:
		$a0 = { 60 B8 ?? ?? ?? 00 B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3  }
	$a1 = { 60 B8 ?? ?? ?? ?? B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? ?? C3  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Obsidium_V1_3_0_4____Obsidium_Software_____Sign_By_haggar
{
strings:
		$a0 = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 01 ?? E8 3B 26 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Lock_NT_v2_04
{
strings:
		$a0 = { EB ?? CD ?? ?? ?? ?? ?? CD ?? ?? ?? ?? ?? EB ?? EB ?? EB ?? EB ?? CD ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 50 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Lock_NT_v2_01
{
strings:
		$a0 = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Lock_NT_v2_03
{
strings:
		$a0 = { EB 02 C7 85 1E EB 03 CD 20 C7 9C EB 02 69 B1 60 EB 02 EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule Inno_Setup_Module_v3_0_4_beta_v3_0_6_v3_0_7
{
strings:
		$a0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C  }

condition:
		$a0 at entrypoint
}
	
	
rule VProtector_V1_1____vcasm
{
strings:
		$a0 = { B8 1A ED 41 00 B9 EC EB 41 00 50 51 E8 74 00 00 00 E8 51 6A 00 00 58 83 E8 10 B9 B3 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule NoobyProtect_V1_2_9_0____Nooby_____Sign_By_fly___20090218
{
strings:
		$a0 = { E9 ?? 00 00 00 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 53 45 20 31 2E 32 2E 39 2E 30  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_Delphi_v6_0___v7_0
{
strings:
		$a0 = { 55 8B EC 83 C4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  }
	$a1 = { BA ?? ?? ?? ?? 83 7D 0C 01 75 ?? 50 52 C6 05 ?? ?? ?? ?? ?? 8B 4D 08 89 0D ?? ?? ?? ?? 89 4A 04  }
	$a2 = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 ?? ?? FB FF A1 ?? ?? ?? ?? 8B ?? E8 ?? ?? FF FF 8B 0D ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 00 8B 15 ?? ?? ?? ?? E8 ?? ?? FF FF A1 ?? ?? ?? ?? 8B ?? E8 ?? ?? FF FF E8 ?? ?? FB FF 8D 40  }
	$a3 = { 55 8B EC 83 C4 F0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint
}
	
	
rule Reg2Exe_2_25___by_Jan_Vorel
{
strings:
		$a0 = { 68 68 00 00 00 68 00 00 00 00 68 70 7D 40 00 E8 AE 20 00 00 83 C4 0C 68 00 00 00 00 E8 AF 52 00 00 A3 74 7D 40 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 9C 52 00 00 A3 70 7D 40 00 E8 24 50 00 00 E8 E2 48 00 00 E8 44 34 00 00 E8 54 28 00 00 E8 98 27 00 00 E8 93 20 00 00 68 01 00 00 00 68 D0 7D 40 00 68 00 00 00 00 8B 15 D0 7D 40 00 E8 89 8F 00 00 B8 00 00 10 00 68 01 00 00 00 E8 9A 8F 00 00 FF 35 A4 7F 40 00 68 00 01 00 00 E8 3A 23 00 00 8D 0D A8 7D 40 00 5A E8 5E 1F 00 00 FF 35 A8 7D 40 00 68 00 01 00 00 E8 2A 52 00 00 A3 B4 7D 40 00 FF 35 A4 7F 40 00 FF 35 B4 7D 40 00 FF 35 A8 7D 40 00 E8 5C 0C 00 00 8D 0D A0 7D 40 00 5A E8 26 1F 00 00 FF 35  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_MSVC___6_0_DLL_____emadicius
{
strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 5F 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_EXE32Pack_1_3x_____emadicius
{
strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC 56 3B D2 74 02 81 85 57 E8 00 00 00 00 3B DB 74 01 90 83 C4 14 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_CAB_SFX_module
{
strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? 10 00 01 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E 22 75 0D ?? EB 0A 3C 20  }

condition:
		$a0 at entrypoint
}
	
	
rule PrincessSandy_v1_0_eMiNENCE_Process_Patcher_Patch
{
strings:
		$a0 = { 68 27 11 40 00 E8 3C 01 00 00 6A 00 E8 41 01 00 00 A3 00 20 40 00 8B 58 3C 03 D8 0F B7 43 14 0F B7 4B 06 8D 7C 18 18 81 3F 2E 4C 4F 41 74 0B 83 C7 28 49 75 F2 E9 A7 00 00 00 8B 5F 0C 03 1D 00 20 40 00 89 1D 04 20 40 00 8B FB 83 C7 04 68 4C 20 40 00 68 08 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 57 6A 00 E8 CE 00 00 00 85 C0 74 78 BD 50 C3 00 00 8B 3D 04 20 40 00 8B 07 8D 3C 07 83 C7 04 89 3D 04 20 40 00 8B 0F 83 C7 04 8B 1F 83 C7 04 4D 85 ED 74 57 60 6A 00 51 68 5C 20 40 00 53 FF 35 4C 20 40 00 E8 93 00 00 00 85 C0 61 74 E1 8B C1 60 BE 5C 20 40 00 F3 A6 74 03 61 EB D2 60 6A 00 50 57 53 FF 35 4C 20 40 00 E8 7A 00 00 00 85 C0 74 20 61 83 3C 07 00 74 2D 03 F8 EB A8 B8 5E 21 40 00 EB 13 B8 7C 21 40 00 EB 0C B8 9E 21 40 00 EB 05 B8 CF 21 40 00 6A 00 68 56  }

condition:
		$a0 at entrypoint
}
	
	
rule MoleBox_V2_3X____MoleStudio_com_____Sign_By_fly
{
strings:
		$a0 = { E8 00 00 00 00 60 E8 4F 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_85
{
strings:
		$a0 = { 55 8B EC 6A FF 68 68 ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24  }

condition:
		$a0 at entrypoint
}
	
	
rule yoda_s_Crypter_1_3____Ashkbiz_Danehkar
{
strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 81 E9 C6 28 40 00 8B D5 81 C2 C6 28 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC  }

condition:
		$a0 at entrypoint
}
	
	
rule EncryptPE_V2_2007_4_11_V2_2008_6_10____WFS_____Sign_By_fly__20080610
{
strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 1B 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule HPA
{
strings:
		$a0 = { E8 ?? ?? 5E 8B D6 83 ?? ?? 83 ?? ?? 06 0E 1E 0E 1F 33 FF 8C D3  }

condition:
		$a0 at entrypoint
}
	
	
rule Ste_lth_PE_1_01____BGCorp
{
strings:
		$a0 = { BA ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACK_v3_05c4__Modified_
{
strings:
		$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3  }

condition:
		$a0 at entrypoint
}
	
	
rule PEtite_v2_0
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 18 8B CC 8D A0 54 BC ?? ?? 8B C3 8D 90 E0 15 ?? ?? 68  }

condition:
		$a0 at entrypoint
}
	
	
rule Silicon_Realms_Install_Stub
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? 92 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? ?? 40 00 33 D2 8A D4 89 15 ?? ?? 40 00 8B C8 81 E1 FF 00 00 00 89 0D ?? ?? 40 00 C1 E1 08 03 CA 89 0D ?? ?? 40 00 C1 E8 10 A3 ?? ?? 40 00 33 F6 56 E8 ?? ?? 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 ?? ?? 00 00 FF 15 ?? 91 40 00 A3 ?? ?? 40 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 ?? ?? FF FF 89 75 D0 8D 45 A4 50 FF 15 ?? 91 40 00 E8 ?? ?? 00 00 89 45 9C F6 45 D0 01 74 06 0F B7 45 D4 EB 03 6A 0A 58 50 FF 75 9C 56 56 FF 15 ?? 91 40 00 50 E8 ?? ?? FF FF 89 45 A0 50 E8 ?? ?? FF FF 8B 45 EC 8B 08 8B 09 89 4D 98 50 51 E8 ?? ?? 00 00 59 59 C3 8B 65 E8 FF 75 98 E8 ?? ?? FF FF 83 3D ?? ?? 40 00 01 75 05  }

condition:
		$a0 at entrypoint
}
	
	
rule BlackEnergy_DDoS_Bot_Crypter
{
strings:
		$a0 = { 55 ?? ?? 81 EC 1C 01 00 00 53 56 57 6A 04 BE 00 30 00 00 56 FF 35 00 20 11 13 6A 00 E8 ?? 03 00 00 ?? ?? 83 C4 10 ?? FF 89 7D F4 0F  }

condition:
		$a0 at entrypoint
}
	
	
rule ActiveMARKrule__TM__R5_31_1140____Trymedia
{
strings:
		$a0 = { 79 11 7F AB 9A 4A 83 B5 C9 6B 1A 48 F9 27 B4 25  }

condition:
		$a0 at entrypoint
}
	
	
rule Packman_V0_0_0_1____Bubbasoft_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? 48  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Keypress_1212
{
strings:
		$a0 = { E8 ?? ?? E8 ?? ?? E8 ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EA ?? ?? ?? ?? 1E 33 DB 8E DB BB  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_v1_1_1_1
{
strings:
		$a0 = { EB 02 ?? ?? E8 E7 1C 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_v1_18_Basic_DLL_rule__LZMA_____Ap0x
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A  }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoiner_1_5_2__Stub_engine_1_6_____GlOFF
{
strings:
		$a0 = { E8 46 FD FF FF 50 E8 0C 00 00 00 FF 25 08 20 40 00 FF 25 0C 20 40 00 FF 25 10 20 40 00 FF 25 14 20 40 00 FF 25 18 20 40 00 FF 25 1C 20 40 00 FF 25 20 20 40 00 FF 25 24 20 40 00 FF 25 28 20 40 00 FF 25 00 20 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___V8_0
{
strings:
		$a0 = { 6A 14 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 94 00 00 00 53 6A 00 8B ?? ?? ?? ?? ?? FF D7 50 FF ?? ?? ?? ?? ?? 8B F0 85 F6 75 0A 6A 12 E8 ?? ?? ?? ?? 59 EB 18 89 1E 56 FF ?? ?? ?? ?? ?? 56 85 C0 75 14 50 FF D7 50 FF ?? ?? ?? ?? ?? B8  }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor_v1_2_0b
{
strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? 00 2B 05 84 ?? ?? 00 A3 ?? ?? ?? 00 83 3D ?? ?? ?? 00 00 74 16 A1 ?? ?? ?? 00 03 05 80 ?? ?? 00 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? 00 01 00 00 00 68 04 01 00 00 8D 85 F0 FE FF FF 50 6A 00 FF 15 ?? ?? ?? 00 8D 84 05 EF FE FF FF 89 85 38 FE FF FF 8B 85 38 FE FF FF 0F BE 00 83 F8 5C  }

condition:
		$a0 at entrypoint
}
	
	
rule Trivial173_by_SMT_SMF
{
strings:
		$a0 = { EB ?? ?? 28 54 72 69 76 69 61 6C 31 37 33 20 62 79 20 53 4D 54 2F 53 4D 46 29  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v32a____emadicius
{
strings:
		$a0 = { EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31  }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptor_v1_3b_____Vaska
{
strings:
		$a0 = { 61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___DLL
{
strings:
		$a0 = { 53 55 56 8B 74 24 14 85 F6 57 B8 01 00 00 00  }
	$a1 = { 53 56 57 BB 01 ?? ?? ?? 8B ?? 24 14  }
	$a2 = { 53 B8 01 00 00 00 8B 5C 24 0C 56 57 85 DB 55 75 12 83 3D ?? ?? ?? ?? ?? 75 09 33 C0  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule PEncrypt_2_0____junkcode
{
strings:
		$a0 = { EB 25 00 00 F7 BF 00 00 00 00 00 00 00 00 00 00 12 00 E8 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 00 00 E8 00 00 00 00 5D 81 ED 2C 10 40 00 8D B5 14 10 40 00 E8 33 00 00 00 89 85 10 10 40 00 BF 00 00 40 00 8B F7 03 7F 3C 8B 4F 54 51 56 8D 85  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_19_Dll__aPlib_0_43_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 89 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 48 04 00 00 00 74 0E 83 BD 4C 04 00 00 00 74 05 E8 B8 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 D1 03 00 00 89 85 5C 04 00 00 5B FF B5 5C 04 00 00 56 FF D3 83 C4 08 8B B5 5C 04 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 E9 94 00 00 00 56 FF 95 C9 03 00 00 85 C0 0F 84 B4 00 00 00 89 85 54 04 00 00 8B C6 EB 5B 8B 85 58 04 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 58 04 00 00 C7 00 20 20 20 00 EB 06 FF B5 58 04 00 00 FF B5 54 04 00 00 FF 95 CD 03 00 00 85 C0 74 71 89 07 83 C7 04 8B 85 58 04 00 00 EB 01 40 80 38 00 75 FA 40 89 85 58 04 00 00 66 81 78 02 00 80 74 A5 80 38 00 75 A0 EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 80 3E 01 0F 85 63 FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 5C 04 00 00 FF 95 D5 03 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule PEtite_v2_2
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_12_V1_14__LZMA_4_30_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB ?? 60  }

condition:
		$a0 at entrypoint
}
	
	
rule PEtite_v2_1
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_PEBundle_0_2___3_x_____emadicius
{
strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin_V0_1____cyberbob_____Sign_By_fly___20080312
{
strings:
		$a0 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 ?? ?? ?? ?? ?? 53 8F 85 ?? ?? ?? ?? BB ?? ?? ?? ?? B9 A5 08 00 00 8D ?? ?? ?? ?? ?? 4F 30 1C 39 FE CB E2 F9 68 2D 01 00 00 59 8D ?? ?? ?? ?? ?? C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 ?? ?? ?? ?? 4F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_2_rule__ZCode_1_01______Anorganix
{
strings:
		$a0 = { E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule SVK_Protector_v1_32__Eng_____Pavol_Cerven
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E  }

condition:
		$a0 at entrypoint
}
	
	
rule PassLock_2000_v1_0__Eng_____Moonlight_Software
{
strings:
		$a0 = { 55 8B EC 53 56 57 BB 00 50 40 00 66 2E F7 05 34 20 40 00 04 00 0F 85 98 00 00 00 E8 1F 01 00 00 C7 43 60 01 00 00 00 8D 83 E4 01 00 00 50 FF 15 F0 61 40 00 83 EC 44 C7 04 24 44 00 00 00 C7 44 24 2C 00 00 00 00 54 FF 15 E8 61 40 00 B8 0A 00 00 00 F7 44 24  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Predator_2448
{
strings:
		$a0 = { 0E 1F BF ?? ?? B8 ?? ?? B9 ?? ?? 49 ?? ?? ?? ?? 2A C1 4F 4F ?? ?? F9 CC  }

condition:
		$a0 at entrypoint
}
	
	
rule MEGALITE_v1_20a
{
strings:
		$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 2D 73 ?? 72 ?? B4 09 BA ?? ?? CD 21 CD 90  }

condition:
		$a0 at entrypoint
}
	
	
rule DEF_1_0____bart_xt
{
strings:
		$a0 = { BE ?? ?? 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor_2_3_9_DLL__compressed_resources_
{
strings:
		$a0 = { 50 68 ?? ?? ?? ?? 58 C1 C0 0F E9 ?? ?? ?? 00 87 04 24 58 89 45 FC E9 ?? ?? ?? FF FF 05 ?? ?? ?? ?? E9 ?? ?? ?? 00 C1 C3 18 E9 ?? ?? ?? ?? 8B 55 08 09 42 F8 E9 ?? ?? ?? FF 83 7D F0 01 0F 85 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 34 24 5E 8B 45 FC 33 D2 56 8B F2 E9 ?? ?? ?? 00 BA ?? ?? ?? ?? E8 ?? ?? ?? 00 A3 ?? ?? ?? ?? C3 E9 ?? ?? ?? 00 C3 83 C4 04 C3 E9 ?? ?? ?? FF 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 ?? ?? ?? 00 E9 ?? ?? ?? FF C1 C2 03 81 CA ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 03 C2 5A E9 ?? ?? ?? FF 81 E7 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 81 C7 ?? ?? ?? ?? 89 07 E9 ?? ?? ?? ?? 0F 89 ?? ?? ?? ?? 87 14 24 5A 50 C1 C8 10  }

condition:
		$a0 at entrypoint
}
	
	
rule Sexe_Crypter_1_1___by_santasdad
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 D8 39 00 10 E8 30 FA FF FF 33 C0 55 68 D4 3A 00 10 64 FF 30 64 89 ?? ?? ?? ?? E4 3A 00 10 A1 00 57 00 10 50 E8 CC FA FF FF 8B D8 53 A1 00 57 00 10 50 E8 FE FA FF FF 8B F8 53 A1 00 57 00 10 50 E8 C8 FA FF FF 8B D8 53 E8 C8 FA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 14 57 00 10 E8 AD F6 FF FF B8 14 57 00 10 E8 9B F6 FF FF 8B CF 8B D6 E8 DA FA FF FF 53 E8 84 FA FF FF 8D 4D EC BA F8 3A 00 10 A1 14 57 00 10 E8 0A FB FF FF 8B 55 EC B8 14 57 00 10 E8 65 F5 FF FF B8 14 57 00 10 E8 63 F6 FF FF E8 52 FC FF FF 33 C0 5A 59 59 64 89 10 68 DB 3A 00 10 8D 45 EC E8 ED F4 FF FF C3 E9 83 EF FF FF EB F0 5F 5E 5B E8 ED F3 FF FF 00 53 45 54 54 49 4E 47 53 00 00 00 00 FF FF FF FF 12 00 00 00 6B 75 74 68 37 36 67 62 62 67 36 37 34 76 38 38 67 79  }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACK_v3_05c4__Extractable___Virus_Shield_
{
strings:
		$a0 = { 03 05 40 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_Full_Edition_1_17_iBox_rule__LZMA_____Ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 67 30 00 00 8D 9D 66 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v4_20____Silicon_Realms_Toolworks
{
strings:
		$a0 = { 55 8B EC 6A FF 68 F8 8E 4C 00 68 F0 EA 49 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4C 00 33 D2 8A D4 89 15 84 A5 4C 00 8B C8 81 E1 FF 00 00 00 89 0D 80 A5 4C 00 C1 E1 08 03 CA 89 0D 7C A5 4C 00 C1 E8 10 A3 78 A5  }

condition:
		$a0 at entrypoint
}
	
	
rule codeCrypter_0_31____Tibbar
{
strings:
		$a0 = { 50 58 53 5B 90 BB ?? ?? ?? 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_60b2
{
strings:
		$a0 = { 55 8B EC 6A FF 68 90 ?? ?? ?? 68 24 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 60 ?? ?? ?? 33 D2 8A D4 89 15 3C  }

condition:
		$a0 at entrypoint
}
	
	
rule Sentinel_Keys_Shell_Client_Library__V1_2_0_0____SafeNet_Inc______Sign_By_fly___20090524
{
strings:
		$a0 = { 55 8B EC A1 ?? ?? ?? ?? 56 85 C0 57 0F 85 A9 18 00 00 A1 ?? ?? ?? ?? 33 FF BE 01 00 00 00 3B C7 89 35 ?? ?? ?? ?? 0F 85 6A 07 00 00 75 03 74 01 ?? 83 EC 08 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 81 7C 24 3C 7C 03 7D 01 E8 2C FB FF FF 7E 03 7F 01 ?? 89 ?? ?? ?? ?? ?? 72 03 73 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 7C 24 28 75 03 74 01 A1 ?? ?? ?? ?? 25 07 00 00 80 79 05 48 83 C8 F8 40 A3 ?? ?? ?? ?? 7C 03 7D 01 ?? ?? ?? ?? ?? ?? ?? 74 17 75 03 74 01 7A 8B ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 2B C1 A3 ?? ?? ?? ?? 75 03 74 01 5E FF 15  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_60b1
{
strings:
		$a0 = { 55 8B EC 6A FF 68 50 ?? ?? ?? 68 74 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 FC  }

condition:
		$a0 at entrypoint
}
	
	
rule CrypKey_v5___v6
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 58 83 E8 05 50 5F 57 8B F7 81 EF ?? ?? ?? ?? 83 C6 39 BA ?? ?? ?? ?? 8B DF B9 0B ?? ?? ?? 8B 06  }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACK_v3_05c4__Extractable_
{
strings:
		$a0 = { 03 05 00 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_1_3_0_17____Obsidium_software
{
strings:
		$a0 = { EB 02 ?? ?? E8 28 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_PCGuard_4_03_4_15_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_tElock_0_61_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 F3 EB FF E0 83 C0 28 50 E8 00 00 00 00 5E B3 33 8D 46 0E 8D 76 31 28 18 F8 73 00 C3 8B FE B9 3C 02  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_V5_0X____Silicon_Realms_Toolworks_____Sign_By_fly
{
strings:
		$a0 = { E8 E3 40 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 44 15 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 36 13 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 C7 12 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 48 11 00 00 59 89 7D FC ?? 75 08 E8 01 49 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 66 D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 AF F9 FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 EE 0F 00 00 59 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACK_v3_05c4__Unextractable___Password_checking_
{
strings:
		$a0 = { 03 05 80 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_Modifier_v0_1x
{
strings:
		$a0 = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD  }

condition:
		$a0 at entrypoint
}
	
	
rule Metrowerks_CodeWarrior_v2_0__Console_
{
strings:
		$a0 = { 55 89 E5 55 B8 FF FF FF FF 50 50 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule BeRo_Tiny_Pascal____BeRo
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 20 43 6F 6D 70 69 6C 65 64 20 62 79 3A 20 42 65 52 6F 54 69 6E 79 50 61 73 63 61 6C 20 2D 20 28 43 29 20 43 6F 70 79 72 69 67 68 74 20 32 30 30 36 2C 20 42 65 6E 6A 61 6D 69 6E 20 27 42 65 52 6F 27 20 52 6F 73 73 65 61 75 78 20  }

condition:
		$a0 at entrypoint
}
	
	
rule JAM_v2_11
{
strings:
		$a0 = { 50 06 16 07 BE ?? ?? 8B FE B9 ?? ?? FD FA F3 2E A5 FB 06 BD ?? ?? 55 CB  }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoiner_1_5_3__Stub_engine_1_7_1_____GlOFF
{
strings:
		$a0 = { E8 02 FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A8 10 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_21__LZMA_4_30_____ap0x_____Sign_By_fly___20080504
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 E0 0C 00 00 EB 0C 8B 85 DC 0C 00 00 89 85 E0 0C 00 00 E8 87 01 00 00 8D B5 08 0D 00 00 8D 9D C6 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 71 0C 00 00 89 85 D8 0C 00 00 E8 98 01 00 00 EB 20 60 8B 85 E0 0C 00 00 FF B5 D8 0C 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD EC 0C 00 00 00 74 0E 83 BD F0 0C 00 00 00 74 05 E8 31 02 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 71 0C 00 00 89 85 04 0D 00 00 5B 60 FF B5 D8 0C 00 00 56 FF B5 04 0D 00 00 FF D3 61 8B B5 04 0D 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD E0 0C 00 00 83 C0 04 89 85 00 0D 00 00 EB 72 56 FF 95 69 0C 00 00 0B C0 75 05 E8 25 03 00 00 85 C0 0F 84 AC 00 00 00 89 85 FC 0C 00 00 8B C6 EB 2E 8B 85 00 0D 00 00 8B 00 50 FF B5 FC 0C 00 00 E8 6D 02 00 00 85 C0 0F 84 86 00 00 00 89 07 83 85 00 0D 00 00 04 83 C7 04 8B 85 00 0D 00 00 83 38 00 75 CD EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD E0 0C 00 00 83 C0 04 89 85 00 0D 00 00 80 3E 01 75 89 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF B5 04 0D 00 00 FF 95 75 0C 00 00 68 ?? ?? ?? ?? 6A 00 FF B5 04 0D 00 00 FF 95 75 0C 00 00 68 ?? ?? ?? ?? 6A 00 FF B5 D8 0C 00 00 FF 95 75 0C 00 00 E8 A0 00 00 00 E8 9B 01 00 00 61 E9 ?? ?? ?? ?? ?? 61 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_5_4____Obsidium_Software_____Sign_By_fly___200800207
{
strings:
		$a0 = { EB 03 ?? ?? ?? E8 2D 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 25 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 02 ?? ?? 58 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 5B 28 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule DalKrypt_1_0___by_DalKiT
{
strings:
		$a0 = { 68 00 10 40 00 58 68 ?? ?? ?? 00 5F 33 DB EB 0D 8A 14 03 80 EA 07 80 F2 04 88 14 03 43 81 FB ?? ?? ?? 00 72 EB FF E7  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE_v1_00__v1_03
{
strings:
		$a0 = { B8 ?? ?? BA ?? ?? 8C DB 03 D8 3B  }

condition:
		$a0 at entrypoint
}
	
	
rule WARNING____TROJAN____XiaoHui
{
strings:
		$a0 = { 60 9C E8 00 00 00 00 5D B8 ?? 85 40 00 2D ?? 85 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Reflexive_Arcade_Wrapper
{
strings:
		$a0 = { 55 8B EC 6A FF 68 98 68 42 00 68 14 FA 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 F8 50 42 00 33 D2 8A D4 89 15 3C E8 42 00 8B C8 81 E1 FF 00 00 00 89 0D 38 E8 42 00 C1 E1 08 03 CA 89 0D 34 E8 42 00 C1 E8 10 A3 30 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoiner_1_5_3__Stub_engine_1_7_____GlOFF
{
strings:
		$a0 = { E8 33 FD FF FF 50 E8 0D 00 00 00 CC FF 25 08 20 40 00 FF 25 0C 20 40 00 FF 25 10 20 40 00 FF 25 14 20 40 00 FF 25 18 20 40 00 FF 25 1C 20 40 00 FF 25 20 20 40 00 FF 25 24 20 40 00 FF 25 28 20 40 00 FF 25 00 20 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule flat_assembler_v1_5x
{
strings:
		$a0 = { 6A 00 FF 15 ?? ?? 40 00 A3 ?? ?? 40 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___v6_0_DLL
{
strings:
		$a0 = { 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 51 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4D ?? ?? ?? ?? 02  }
	$a1 = { 83 7C 24 08 01 75 09 8B 44 24 04 A3 ?? ?? 00 10 E8 8B FF FF FF  }
	$a2 = { 55 8D 6C ?? ?? 81 EC ?? ?? ?? ?? 8B 45 ?? 83 F8 01 56 0F 84 ?? ?? ?? ?? 85 C0 0F 84  }
	$a3 = { 55 8B EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint
}
	
	
rule Thinstall_Embedded_V2_312____Jitit_____Sign_By_fly
{
strings:
		$a0 = { 6A 00 FF 15 ?? ?? ?? ?? E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin_V1_3_betaX____cyberbob_____Sign_By_fly___20080311
{
strings:
		$a0 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 ?? EB FB ?? ?? ?? ?? ?? ?? ?? 8B 42 3C 03 C2 ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_2____Obsidium_Software
{
strings:
		$a0 = { EB 02 ?? ?? E8 77 1E 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PEtite_v1_4
{
strings:
		$a0 = { 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 14 8B CC  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_v0_42
{
strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 52 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Kuku_448
{
strings:
		$a0 = { AE 75 ED E2 F8 89 3E ?? ?? BA ?? ?? 0E 07 BF ?? ?? EB  }

condition:
		$a0 at entrypoint
}
	
	
rule PEtite_v1_3
{
strings:
		$a0 = { 66 9C 60 50 8D 88 ?? F0 ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 68 ?? ?? ?? ?? 53 50 80 04 24 08 50 80 04 24 42  }

condition:
		$a0 at entrypoint
}
	
	
rule PEtite_v1_2
{
strings:
		$a0 = { 9C 60 E8 CA ?? ?? ?? 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08  }

condition:
		$a0 at entrypoint
}
	
	
rule Petite_1_4_____c_1998_99_Ian_Luck
{
strings:
		$a0 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC 8D A0 54 BC 00 00 50 8B C3 8D 90 ?? 16 00 00 68 00 00 ?? ?? 51 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 D8 14 00 00 8B 44 24 18 F6  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_6_4____Obsidium_Software_____Sign_By_fly___20090428
{
strings:
		$a0 = { EB 02 ?? ?? 50 EB 04 ?? ?? ?? ?? E8 29 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 1E EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 64 FF 30 EB 02 ?? ?? 64 89 20 EB 01 ?? EB 01 ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 ?? ?? ?? ?? EB 02 ?? ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__REALBasic______Anorganix
{
strings:
		$a0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule EmbedPE_V1_X____cyclotron
{
strings:
		$a0 = { 83 EC 50 60 68 ?? ?? ?? ?? E8 ?? ?? 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule MinGW_GCC_3_x
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? ?? E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? 55  }

condition:
		$a0 at entrypoint
}
	
	
rule SoftSentry_v3_0
{
strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 E9 B0 06  }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoiner_Small__build_014_021_024_027_____GlOFF
{
strings:
		$a0 = { E8 ?? ?? FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule y0da_s_Crypter_v1_x___Modified
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 ?? ?? 00 00 8D BD ?? ?? ?? ?? 8B F7 AC  }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoiner_Small__build_023_____GlOFF
{
strings:
		$a0 = { E8 E1 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v1_04b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D ?? ?? 80 BD 08 9D  }

condition:
		$a0 at entrypoint
}
	
	
rule UPack_v0_11
{
strings:
		$a0 = { BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 1C F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 03 B3 00 8D 1C 5B 8D 9C 9E 0C 10 00 00 B0 01 67 E3 29 8B D7 2B 56 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF D5 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 55 CC 33 C9 E9 DF 00 00 00 8B 5E 0C 83 C2 30 FF D5 73 50 83 C2 30 FF D5 72 1B 83 C2 30 FF D5 72 2B 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 46 0C B1 80 8A 00 EB CF 83 C2 60 FF D5 87 5E 10 73 0D 83 C2 30 FF D5 87 5E 14 73 03 87 5E 18 3C 07 B0 08 72 02 B0 0B 50 53 8D 96 7C 07 00 00 FF 55 D0 5B 91 EB 77 3C 07 B0 07 72 02 B0 0A 50 87 5E 10 87 5E 14 89 5E 18 8D 96 C4 0B 00 00 FF 55 D0 50 48  }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin_v0_7____Cyberbob
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF  }

condition:
		$a0 at entrypoint
}
	
	
rule LCC_Win32_DLL
{
strings:
		$a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 ?? ?? ?? FF 75 10 FF 75 0C FF 75 08 A1  }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACK_v3_02__v3_02a__Extractable_
{
strings:
		$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 33 C9 B1 ?? 51 06 06 BB ?? ?? 53 8C D3  }

condition:
		$a0 at entrypoint
}
	
	
rule Themida_WinLicense_V1_8_2_0_______Oreans_Technologies_____Sign_By_fly
{
strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor_Light_V1_7_0_1____CGSoftLabs_____Sign_By_fly___20090603
{
strings:
		$a0 = { 55 8B EC 81 EC 84 02 00 00 53 56 57 83 A5 A8 FD FF FF 00 F3 EB 0C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 78 60 00 75 14 6A 10 68 F0 ?? ?? ?? 68 78 ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? E8 F0 FE FF FF A3 ?? ?? ?? ?? 68 04 01 00 00 8D 85 D8 FD FF FF 50 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8D 84 05 D7 FD FF FF 89 85 AC FD FF FF 8B 85 AC FD FF FF 0F BE 00 83 F8 5C  }

condition:
		$a0 at entrypoint
}
	
	
rule COP_v1_0__c__1988
{
strings:
		$a0 = { BF ?? ?? BE ?? ?? B9 ?? ?? AC 32 ?? ?? ?? AA E2 ?? 8B ?? ?? ?? EB ?? 90  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_20_Dll__LZMA_4_30_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 AA 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 9C 0C 00 00 EB 0C 8B 85 98 0C 00 00 89 85 9C 0C 00 00 8D B5 C4 0C 00 00 8D 9D 82 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 2D 0C 00 00 89 85 94 0C 00 00 E8 59 01 00 00 EB 20 60 8B 85 9C 0C 00 00 FF B5 94 0C 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD A8 0C 00 00 00 74 0E 83 BD AC 0C 00 00 00 74 05 E8 F2 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 2D 0C 00 00 89 85 C0 0C 00 00 5B 60 FF B5 94 0C 00 00 56 FF B5 C0 0C 00 00 FF D3 61 8B B5 C0 0C 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 9C 0C 00 00 83 C0 04 89 85 BC 0C 00 00 EB 72 56 FF 95 25 0C 00 00 0B C0 75 05 E8 E6 02 00 00 85 C0 0F 84 AB 00 00 00 89 85 B8 0C 00 00 8B C6 EB 2E 8B 85 BC 0C 00 00 8B 00 50 FF B5 B8 0C 00 00 E8 2E 02 00 00 85 C0 0F 84 85 00 00 00 89 07 83 85 BC 0C 00 00 04 83 C7 04 8B 85 BC 0C 00 00 83 38 00 75 CD EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD 9C 0C 00 00 83 C0 04 89 85 BC 0C 00 00 80 3E 01 75 89 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 C0 0C 00 00 FF 95 31 0C 00 00 68 00 80 00 00 6A 00 FF B5 C0 0C 00 00 FF 95 31 0C 00 00 68 00 80 00 00 6A 00 FF B5 94 0C 00 00 FF 95 31 0C 00 00 E8 61 00 00 00 E8 5C 01 00 00 61 E9 ?? ?? ?? ?? 61 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule PEncrypt_1_0____JunkCode
{
strings:
		$a0 = { 60 9C BE 00 10 40 00 8B FE B9 ?? ?? ?? ?? BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 E9 ?? ?? ?? FF  }

condition:
		$a0 at entrypoint
}
	
	
rule ExeJoiner_1_0____Yoda
{
strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 68 04 11 40 00 6A 00 E8 1A 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 68 04 11 40 00 E8 EC 02 00 00 83 F8 FF 0F 84 83 02 00 00 A3 08 12 40 00 6A 00 50 E8 E2 02 00 00 83 F8 FF 0F 84 6D 02 00 00 A3 0C 12 40 00 8B D8 83 EB 04 6A 00 6A 00 53 FF 35 08 12 40 00 E8 E3 02 00 00 6A 00 68 3C 12 40 00 6A 04 68 1E 12 40 00 FF 35 08 12 40 00 E8 C4 02 00 00 83 EB 04 6A 00 6A 00 53 FF 35 08 12 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Splash_Bitmap_v1_00__With_Unpack_Code______BoB___Bobsoft
{
strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 6A 40  }

condition:
		$a0 at entrypoint
}
	
	
rule aPack_v0_82
{
strings:
		$a0 = { 1E 06 8C CB BA ?? ?? 03 DA 8D ?? ?? ?? FC 33 F6 33 FF 48 4B 8E C0 8E DB  }

condition:
		$a0 at entrypoint
}
	
	
rule QinYingShieldLicense_V1_0X_V1_21____Lei_Peng____Sign_By_fly___20080122
{
strings:
		$a0 = { E8 00 00 00 00 58 05 ?? ?? ?? ?? 9C 50 C2 04 00 55 8B EC 56 57 53 34 99 47 49 34 33 EF 31 CD F5 B0 CB B5 B0 A3 A1 A3 A1 B9 FE B9 FE B9 FE B9 FE BF C9 CF A7 D1 BD A3 AC C4 E3 B2 BB D6 AA B5 C0 D5 E2 C0 EF B5 C4 D6 B8 C1 EE CA C7 CA B2 C3 B4 A3 A1 B9 FE B9 FE B9 FE 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_2_rule__Borland_Delphi_Setup_Module______Anorganix
{
strings:
		$a0 = { 55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Mew_10_exe_coder_1_0_____Northfox_rule__HCC_
{
strings:
		$a0 = { 33 C0 E9 ?? ?? FF FF 6A ?? ?? ?? ?? ?? 70  }

condition:
		$a0 at entrypoint
}
	
	
rule FixupPak_v1_20
{
strings:
		$a0 = { 55 E8 00 00 00 00 5D 81 ED ?? ?? 00 00 BE 00 ?? 00 00 03 F5 BA 00 00 ?? ?? 2B D5 8B DD 33 C0 AC 3C 00 74 3D 3C 01 74 0E 3C 02 74 0E 3C 03 74 0D 03 D8 29 13 EB E7 66 AD EB F6 AD EB F3 AC 0F B6 C8 3C 00 74 06 3C 01 74 09 EB 0A 66 AD 0F B7 C8 EB 03 AD 8B C8 AC 0F B6 C0 03 D8 29 13 E2 FA EB BC 8D 85 ?? ?? 00 00 5D FF E0 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule kryptor_6
{
strings:
		$a0 = { E8 03 ?? ?? ?? E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75 02  }

condition:
		$a0 at entrypoint
}
	
	
rule kryptor_5
{
strings:
		$a0 = { E8 03 ?? ?? ?? E9 EB 6C 58 40 FF E0  }

condition:
		$a0 at entrypoint
}
	
	
rule PEQuake_V0_06___forgot
{
strings:
		$a0 = { E8 A5 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5D 81 ED 05 00 00 00 8D 75 3D 56 FF 55 31 8D B5 81 00 00 00 56 50 FF 55 2D 89 85 8E 00 00 00 6A 04 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 8E 00 00 00 50 8B 9D 7D 00 00 00 03 DD 50 53 E8 04 00 00 00 5A 55 FF E2 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C2 08 00  }

condition:
		$a0 at entrypoint
}
	
	
rule kryptor_9
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5E B9 ?? ?? ?? ?? 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9  }

condition:
		$a0 at entrypoint
}
	
	
rule VIRUS___I_Worm_Hybris
{
strings:
		$a0 = { EB 16 A8 54 ?? ?? 47 41 42 4C 4B 43 47 43 ?? ?? ?? ?? ?? ?? 52 49 53 ?? FC 68 4C 70 40 ?? FF 15  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_PEBundle_2_0x___2_4x_____emadicius
{
strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 83 BD 9C 38 40 00 01 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule StarForce_Protection_Driver____Protection_Technology
{
strings:
		$a0 = { 57 68 ?? 0D 01 00 68 00 ?? ?? 00 E8 50 ?? FF FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Patch_Creation_Wizard_v1_2_Memory_Patch
{
strings:
		$a0 = { 6A 00 E8 9B 02 00 00 A3 7A 33 40 00 6A 00 68 8E 10 40 00 6A 00 6A 01 50 E8 B5 02 00 00 68 5A 31 40 00 68 12 31 40 00 6A 00 6A 00 6A 04 6A 01 6A 00 6A 00 68 A2 30 40 00 6A 00 E8 51 02 00 00 85 C0 74 31 FF 35 62 31 40 00 6A 00 6A 30 E8 62 02 00 00 E8 0B 01 00 00 FF 35 5A 31 40 00 E8 22 02 00 00 FF 35 5E 31 40 00 E8 53 02 00 00 6A 00 E8 22 02 00 00 6A 10 68 F7 30 40 00 68 FE 30 40 00 6A 00 E8 63 02 00 00 6A 00 E8 08 02 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 75 6B 6A 01 FF 35 7A 33 40 00 E8 38 02 00 00 50 6A 01 68 80 00 00 00 FF 75 08 E8 34 02 00 00 68 00 30 40 00 6A 65 FF 75 08 E8 2B 02 00 00 68 51 30 40 00 6A 67 FF 75 08 E8 1C 02 00 00 68 A2 30 40 00 6A 66 FF 75 08 E8 0D 02 00 00 8B 45 08 A3 7E 33 40 00 68 3B 11 40 00 68 E8 03 00 00 68 9A 02 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PCPEC_rule__alpha_
{
strings:
		$a0 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 8B CD 81 ?? ?? ?? ?? ?? 2B ?? ?? ?? ?? ?? 83  }

condition:
		$a0 at entrypoint
}
	
	
rule Macromedia_Windows_Flash_Projector_Player_v4_0
{
strings:
		$a0 = { 83 EC 44 56 FF 15 24 41 43 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C  }

condition:
		$a0 at entrypoint
}
	
	
rule AdFlt2
{
strings:
		$a0 = { 68 00 01 9C 0F A0 0F A8 60 FD 6A 00 0F A1 BE ?? ?? AD  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Ste_lth_PE_1_01______Anorganix
{
strings:
		$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 BA ?? ?? ?? ?? FF E2 BA E0 10 40 00 B8 68 24 1A 40 89 02 83 C2 03 B8 40 00 E8 EE 89 02 83 C2 FD FF E2 2D 3D 5B 20 48 69 64 65 50 45 20 5D 3D 2D 90 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Private_EXE_v2_0a
{
strings:
		$a0 = { 53 E8 00 00 00 00 5B 8B C3 2D  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Hafen_809
{
strings:
		$a0 = { E8 ?? ?? 1C ?? 81 EE ?? ?? 50 1E 06 8C C8 8E D8 06 33 C0 8E C0 26 ?? ?? ?? 07 3D  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__GRUNT_2_Family
{
strings:
		$a0 = { 48 E2 F7 C3 51 53 52 E8 DD FF 5A 5B 59 C3 B9 00 00 E2 FE C3  }

condition:
		$a0 at entrypoint
}
	
	
rule X_Hider_1_0____GlobaL
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 33 C0 89 45 EC B8 54 20 44 44 E8 DF F8 FF FF 33 C0 55 68 08 21 44 44 64 FF 30 64 89 20 8D 55 EC B8 1C 21 44 44 E8 E0 F9 FF FF 8B 55 EC B8 40 ?? ?? 44 E8 8B F5 FF FF 6A 00 6A 00 6A 02 6A 00 6A 01 68 00 00 00 40 A1 40 ?? ?? 44 E8 7E F6 FF FF 50 E8 4C F9 FF FF 6A 00 50 E8 4C F9 FF FF A3 28 ?? ?? 44 E8 CE FE FF FF 33 C0 5A 59 59 64 89 10 68 0F 21 44 44 8D 45 EC E8 F1 F4 FF FF C3 E9 BB F2 FF FF EB F0 E8 FC F3 FF FF FF FF FF FF 0E 00 00 00 63 3A 5C 30 30 30 30 30 30 31 2E 64 61 74 00  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_18__LZMA_4_30_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 ?? 83 3C 37 00 75 E6 83 BD 0D 0B 00 00 00 74 0E 83 BD 11 0B 00 00 00 74 05 E8 F6 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 AA 0A 00 00 89 85 1D 0B 00 00 5B 60 FF B5 F9 0A 00 00 56 FF B5 1D 0B 00 00 FF D3 61 8B B5 1D 0B 00 00 8B C6 EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Protector_0_9_3_____CRYPToCRACk
{
strings:
		$a0 = { 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 75 09 83 EC 04 0F 85 DD 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v4_30___v4_40____Silicon_Realms_Toolworks
{
strings:
		$a0 = { 55 8B EC 6A FF 68 40 ?? ?? 00 68 80 ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 ?? ?? 00 33 D2 8A D4 89 15 30 ?? ?? 00 8B C8 81 E1 FF 00 00 00 89 0D 2C ?? ?? 00 C1 E1 08 03 CA 89 0D 28 ?? ?? 00 C1 E8 10 A3 24  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_20__Eng_____dulek_xt_____Microsoft_Visual_C___6_0___7_0_
{
strings:
		$a0 = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA  }

condition:
		$a0 at entrypoint
}
	
	
rule KGB_SFX
{
strings:
		$a0 = { 60 BE 00 A0 46 00 8D BE 00 70 F9 FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Code_Lock______Anorganix
{
strings:
		$a0 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B E9  }

condition:
		$a0 at entrypoint
}
	
	
rule nPack_V1_1_500_2008_Beta____NEOx_____Sign_By_fly___20080217
{
strings:
		$a0 = { 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8 48 02 00 00 E8 F8 06 00 00 E8 47 06 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 56 57 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B F8 68 ?? ?? ?? ?? 57 FF D6 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 5F A3 ?? ?? ?? ?? 5E C3 56 57 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B F0 BF ?? ?? ?? ?? 56 57 E8 23 FE FF FF 6A ?? 56 57 E8 F4 FC FF FF 83 C4 14 68 ?? ?? ?? ?? 6A ?? 56 FF 15 ?? ?? ?? ?? 5F 5E C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Pohernah_1_0_3___by_Kas
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 2A 27 40 00 31 C0 40 83 F0 06 40 3D 40 1F 00 00 75 07 BE 6A 27 40 00 EB 02 EB EB 8B 85 9E 28 40 00 83 F8 01 75 17 31 C0 01 EE 3D 99 00 00 00 74 0C 8B 8D 86 28 40 00 30 0E 40 46 EB ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 56 57 4F F7 D7 21 FE 89 F0 5F 5E C3 60 83 F0 05 40 90 48 83 F0 05 89 C6 89 D7 60 E8 0B 00 00 00 61 83 C7 08 83 E9 07 E2 F1 61 C3 57 8B 1F 8B 4F 04 68 B9 79 37 9E 5A 42 89 D0 48 C1 E0 05 BF 20 00 00 00 4A 89 DD C1 E5 04 29 E9 8B 6E 08 31 DD 29 E9 89 DD C1 ED 05 31 C5 29 E9 2B 4E 0C 89 CD C1 E5 04 29 EB 8B 2E 31 CD 29 EB 89 CD C1 ED 05 31 C5 29 EB 2B 5E 04 29 D0 4F 75 C8 5F 89 1F 89 4F 04 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v1_80
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 00 00 68 F4 86 00 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v1_83
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 64 84 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v1_82
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 74 81 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Freshbind_v2_0____gFresh
{
strings:
		$a0 = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 1C A0 41 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v1_84
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 40 00 68 F4 86 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_0_12_beta___Dwing
{
strings:
		$a0 = { BE 48 01 40 00 AD ?? ?? ?? A5 ?? C0 33 C9 ?? ?? ?? ?? ?? ?? ?? F3 AB ?? ?? 0A ?? ?? ?? ?? AD 50 97 51 ?? 87 F5 58 8D 54 86 5C ?? D5 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B6 5F FF C1  }

condition:
		$a0 at entrypoint
}
	
	
rule SDProtector_Basic_Pro_Edition_1_10____Randy_Li
{
strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 50 83 EC 08 64 A1 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 83 C4 08 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 64  }

condition:
		$a0 at entrypoint
}
	
	
rule Solidshield_Protector_V1_X____Solidshield_Technologies_____Sign_By_fly
{
strings:
		$a0 = { 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 00 60 89 00 0A 00 00 00 46 33 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PECompact_v2_5_Retail
{
strings:
		$a0 = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Einstein
{
strings:
		$a0 = { 00 42 CD 21 72 31 B9 6E 03 33 D2 B4 40 CD 21 72 19 3B C1 75 15 B8 00 42  }

condition:
		$a0 at entrypoint
}
	
	
rule PECompact_v2_5_Retail__Slim_Loader_
{
strings:
		$a0 = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Macromedia_Windows_Flash_Projector_Player_v3_0
{
strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 94 13 42 00 8B F0 B1 22 8A 06 3A C1 75 13 8A 46 01 46 3A C1 74 04 84 C0 75 F4 38 0E 75 0D 46 EB 0A 3C 20 7E 06  }

condition:
		$a0 at entrypoint
}
	
	
rule Nullsoft_Install_System_v2_0_RC2
{
strings:
		$a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 68 68 92 40 00 56 FF D3 E8 6A FF FF FF 85 C0 0F 84 59 01 00 00 BE 20 E4 42 00 56 FF 15 68 70 40 00 68 5C 92 40 00 56 E8 B9 28 00 00 57 FF 15 BC 70 40 00 BE 00 40 43 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 40 43 00 22 A3 20 EC 42 00 8B C6 75 0A C6 44 24 13 22 B8 01 40 43 00 8B 3D 18 72 40 00 EB 09 3A 4C 24 13 74 09 50 FF D7 8A 08 84 C9 75 F1 50 FF D7 8B F0 89 74 24 1C EB 05 56 FF D7 8B F0 80 3E 20 74 F6 80 3E 2F 75 44 46 80 3E 53 75 0C 8A 46 01 0C 20 3C 20 75 03 83 CD 02 81 3E 4E 43 52  }

condition:
		$a0 at entrypoint
}
	
	
rule PureBasic_DLL____Neil_Hodgson
{
strings:
		$a0 = { 83 7C 24 08 01 75 ?? 8B 44 24 04 A3 ?? ?? ?? 10 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule Inno_Setup_Module
{
strings:
		$a0 = { 49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 00 00 53 54 41 54 49 43  }

condition:
		$a0 at entrypoint
}
	
	
rule MPRESS_V1_07_V1_2X____MATCODE_Software_____Sign_By_fly___20080730
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 05 9E 02 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 8B D6 8B CF E8 56 00 00 00 5E 5A 83 EA 05 2B C9 3B CA 73 26 8B D9 AC 41 24 FE 3C E8 75 F2 43 83 C1 04 AD 0B C0 78 06 3B C2 73 E5 EB 06 03 C3 78 DF 03 C2 2B C3 89 46 FC EB D6 E8 00 00 00 00 5F 81 C7 8D FF FF FF B0 E9 AA B8 9A 02 00 00 AB E8 00 00 00 00 58 05 1C 02 00 00 E9 0C 02 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_Pascal_v7_0_for_Windows
{
strings:
		$a0 = { 9A FF FF 00 00 9A FF FF 00 00 55 89 E5 31 C0 9A FF FF 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PENightMare_2_Beta
{
strings:
		$a0 = { 60 E9 ?? ?? ?? ?? EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A  }

condition:
		$a0 at entrypoint
}
	
	
rule Petite_v2_1__1_
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 66 9C 60 50  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Uddy_2617
{
strings:
		$a0 = { 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? 8C C8 8E D8 8C ?? ?? ?? 2B ?? ?? ?? 03 ?? ?? ?? A3 ?? ?? A1 ?? ?? A3 ?? ?? A1 ?? ?? A3 ?? ?? 8C C8 2B ?? ?? ?? 03 ?? ?? ?? A3 ?? ?? B8 AB 9C CD 2F 3D 76 98  }

condition:
		$a0 at entrypoint
}
	
	
rule SkD_Undetectabler_3__No_FSG_2_Method_____SkD
{
strings:
		$a0 = { 55 8B EC 81 EC 10 02 00 00 68 00 02 00 00 8D 85 F8 FD FF FF 50 6A 00 FF 15 38 10 00 01 50 FF 15 3C 10 00 01 8D 8D F8 FD FF FF 51 E8 4F FB FF FF 83 C4 04 8B 15 ?? 16 00 01 52 A1 ?? 16 00 01 50 E8 50 FF FF FF 83 C4 08 A3 ?? 16 00 01 C7 85 F4 FD FF FF 00 00 00 00 EB 0F 8B 8D F4 FD FF FF 83 C1 01 89 8D F4 FD FF FF 8B 95 F4 FD FF FF 3B 15 ?? 16 00 01 73 1C 8B 85 F4 FD FF FF 8B 0D ?? 16 00 01 8D 54 01 07 81 FA 74 10 00 01 75 02 EB 02 EB C7 8B 85 F4 FD FF FF 50 E8 ?? 00 00 00 83 C4 04 89 85 F0 FD FF FF 8B 8D F0 FD FF FF 89 4D FC C7 45 F8 00 00 00 00 EB 09 8B 55 F8 83 C2 01 89 55 F8 8B 45 F8 3B 85 F4 FD FF FF 73 15 8B 4D FC 03 4D F8 8B 15 ?? 16 00 01 03 55 F8 8A 02 88 01 EB D7 83 3D ?? 16 00 01 00 74  }

condition:
		$a0 at entrypoint
}
	
	
rule Exe_Locker_v1_0_____IonIce
{
strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 3E 8F 85 6C 00 00 00 3E 8F 85 68 00 00 00 3E 8F 85 64 00 00 00 3E 8F 85 60 00 00 00 3E 8F 85 5C 00 00 00 3E 8F 85 58 00 00 00 3E 8F 85 54 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Special_EXE_Pasword_Protector_v1_01__Eng_____Pavol_Cerven
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77 00 00 8D 95 C6 77 00 00 8D 8D FF 77 00 00 55 68 00 20 00 00 51 52 6A 00 FF 95 04 7A 00 00 5D 6A 00 FF 95 FC 79 00 00 8D 8D 60 78 00 00 8D 95 85 01 00 00 55 68 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_20__Eng_____dulek_xt_____Microsoft_Visual_C___6_0_
{
strings:
		$a0 = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3  }

condition:
		$a0 at entrypoint
}
	
	
rule CopyMinder____Microcosm_Ltd_____Sign_By_fly
{
strings:
		$a0 = { 83 25 ?? ?? ?? ?? EF 6A 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? CC FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_53
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 40 ?? ?? ?? ?? 68 54 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 58 33 D2 8A D4 89  }
	$a1 = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 54 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Armadillo_v2_52
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? E0 ?? ?? ?? ?? 68 D4 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 38  }
	$a1 = { 55 8B EC 6A FF 68 E0 ?? ?? ?? 68 D4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 38  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Armadillo_v2_51
{
strings:
		$a0 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_50
{
strings:
		$a0 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_v0_71___v0_72
{
strings:
		$a0 = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E 8D BE FA ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 81 C6 B3 01 ?? ?? EB 0A ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_6_3____Obsidium_Software_____Sign_By_fly___20080730
{
strings:
		$a0 = { EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? E8 ?? 00 00 00 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 26 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 33 C0 EB 02 ?? ?? 64 FF 30 EB 01 ?? 64 89 20 EB 01 ?? EB 02 ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 ?? 00 00 00 EB 03 ?? ?? ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACK_v3_05c4__Unextractable_
{
strings:
		$a0 = { 03 05 00 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_V0_99_V1_0_Private____tE______Sign_By_fly
{
strings:
		$a0 = { E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____MASM32_
{
strings:
		$a0 = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Crunch_PE_Heuristic______Anorganix
{
strings:
		$a0 = { 55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Protection_Plus_vx_x
{
strings:
		$a0 = { 50 60 29 C0 64 FF 30 E8 ?? ?? ?? ?? 5D 83 ED 3C 89 E8 89 A5 14 ?? ?? ?? 2B 85 1C ?? ?? ?? 89 85 1C ?? ?? ?? 8D 85 27 03 ?? ?? 50 8B ?? 85 C0 0F 85 C0 ?? ?? ?? 8D BD 5B 03 ?? ?? 8D B5 43 03 ?? ?? E8 DD ?? ?? ?? 89 85 1F 03 ?? ?? 6A 40 68 ?? 10 ?? ?? 8B 85 28 ?? ?? ?? 50 6A  }

condition:
		$a0 at entrypoint
}
	
	
rule yzpack_V1_1____UsAr_____Sign_By_fly
{
strings:
		$a0 = { 60 33 C0 8D 48 07 50 E2 FD 8B EC 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 8D 40 7C 8B 40 3C 89 45 04 E8 F3 07 00 00 60 8B 5D 04 8B 73 3C 8B 74 33 78 03 F3 56 8B 76 20 03 F3 33 C9 49 92 41 AD 03 C3 52 33 FF 0F B6 10 38 F2  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_v0_37_beta____Dwing
{
strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 37 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 D2 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B 7E 34 0F 82 8E FE FF FF 58 5F 59 E3 1B 8A 07 47 04 18 3C 02 73 F7 8B 07 3C ?? 75 F1 B0 00 0F C8 03 46 38 2B C7 AB E2 E5 5E 5D 59 51 59 46 AD 85 C0 74 1F  }

condition:
		$a0 at entrypoint
}
	
	
rule DSHIELD
{
strings:
		$a0 = { 06 E8 ?? ?? 5E 83 EE ?? 16 17 9C 58 B9 ?? ?? 25 ?? ?? 2E  }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtect_v1_2x
{
strings:
		$a0 = { 00 00 68 01 ?? ?? ?? C3 AA  }

condition:
		$a0 at entrypoint
}
	
	
rule VMware_ThinApp_V4_0_1_2866____VMware_____Sign_By_fly___20090124
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 72 13 00 00 2B C3 50 68 00 00 20 46 68 00 60 00 00 68 58 01 00 00 E8 71 FC FF FF E9 DA FC FF FF 55 8B EC 8B 48 3C 83 EC 0C 53 56 57 8D 7C 01 78 8B 0F 85 C9 74 7E 8B 77 04 83 FE 28 72 76 8D 1C 01 8B 53 18 85 D2 74 6C 8B 43 20 3B C1 72 65 8D 14 90 03 F1 3B F2 72 5C 83 65 FC 00 2B C1 03 C3 83 7B 18 00 89 45 F4 76 4B 8B 4D FC 8B 45 F4 8D 04 88 8B 0F 3B 08 77 31 8B 30 FF 75 08 8B C1 89 45 F8 FF 15 2C 30 20 46 8B 4F 04 03 4D F8 8D 44 30 01 3B C1 77 13 2B 75 F8 FF 75 08 03 F3 56 FF 15 28 30 20 46 85 C0 74 12 FF 45 FC 8B 45 FC 3B 43 18 72 B5 33 C0 5F 5E 5B C9 C3 8B 55 FC 39 53 14 76 F1 8B 43 1C 8B 0F 3B C1 72 E8 8D 04 90 8B 57 04 03 D1 8D 70 04 3B D6 72 D9 2B C1 8B 04 18 EB D4 FF 25 5C 14 20 46 00 00 00 00 56 6A 01 FF 74 24 14 6A 00 FF 74 24 18 E8 DC 07 00 00 8B F0 83 C4 10 85 F6 75 04 33 C0 EB 28 68 AB 14 20 46 E8 0B FF FF FF 59 85 C0 74 ED 8B 4C 24 14 68 5C 14 20 46 FF 74 24 10 03 C6 6A 01 C7 01 56 14 20 46 FF D0 5E C2 10 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PackMan_v0_0_0_1
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 8D A8 ?? ?? FF FF 8D 98 ?? ?? ?? FF 8D ?? ?? 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v2_0____bart_xt
{
strings:
		$a0 = { 87 25 ?? ?? ?? 00 61 94 55 A4 B6 80 FF 13  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v1_05b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_50b3
{
strings:
		$a0 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0  }

condition:
		$a0 at entrypoint
}
	
	
rule BeRoEXEPacker_v1_00_rule__LZBRS_____BeRo___Farbrausch
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 ?? ?? ?? ?? 72 03 A4 EB F2 E8 ?? ?? ?? ?? 8D 51 FF E8 ?? ?? ?? ?? 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33  }

condition:
		$a0 at entrypoint
}
	
	
rule AverCryptor_1_0____os1r1s
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 75 17 40 00 8B BD 9C 18 40 00 8B 8D A4 18 40 00 B8 BC 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 A0 18 40 00 33 C0 51 33 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 A0 18 40 00 8B 85 A8 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 BC 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 98 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3  }

condition:
		$a0 at entrypoint
}
	
	
rule ANDpakk2__apk2__V0_06____Dmitry__AND__Andreev_____Sign_By_fly___20080731
{
strings:
		$a0 = { 60 FC BE ?? ?? ?? ?? BF ?? ?? ?? ?? 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 4D D1 F8 8B E8 EB 09 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 13 C9 75 1A 41 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 73 EA 83 C1 02 81 FD ?? ?? ?? ?? 83 D1 01 56 8D 34 2F F3 A4 5E E9 73 FF FF FF C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Naked_Packer_V1_0____BigBoote_____Sign_By_fly
{
strings:
		$a0 = { 60 FC 0F B6 05 ?? ?? ?? ?? 85 C0 75 31 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9A 00 00 00 A3 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 83 3D ?? ?? ?? ?? 00 75 07 61 FF 25 ?? ?? ?? ?? 61 FF 74 24 04 6A 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? C3 FF 74 24 04 6A 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Trainer_Creation_Kit_v5_Trainer
{
strings:
		$a0 = { 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 40 68 25 45 40 00 E8 3C 02 00 00 50 6A 00 68 40 45 40 00 68 00 10 00 00 68 00 30 40 00 50 E8 54 02 00 00 58 50 E8 17 02 00 00 6A 00 E8 2E 02 00 00 A3 70 45 40 00 68 25 45 40 00 E8 2B 02 00 00 A3 30 45 40 00 68 34 45 40 00 50 E8 15 02 00 00 6A 00 FF 35 30 45 40 00 50 6A 02 E8 4D 02 00 00 A3 74 45 40 00 6A 00 68 D4 10 40 00 6A 00 6A 01 FF 35 70 45 40 00 E8 02 02 00 00 B3 0A FE CB 74 10 FF 35 74 45 40 00 E8 27 02 00 00 83 F8 00 74 EC B3 0A FE CB 74 10 FF 35 30 45 40 00 E8 B7 01 00 00 83 F8 00 74 EC B3 0A FE CB 74 16 68 25 45 40 00 E8 96 01 00 00 83 F8 00 74 ED 6A 00 E8 90 01 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C7 00 00 00 6A 01 FF 35 70 45 40 00 E8 B0 01 00 00 50 6A 01 68 80 00 00 00 FF  }

condition:
		$a0 at entrypoint
}
	
	
rule SVK_Protector_V1_3X____Pavol_Cerven
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E 00 74 03 46 EB F8 46 E2 E3 8B C5 8B 4C 24 20 2B 85 BD 02 00 00 89 85 B9 02 00 00 80 BD B4 02 00 00 01 75 06 8B 8D 0C 61 00 00 89 8D B5 02 00 00 8D 85 0E 03 00 00 8B DD FF E0 55 68 10 10 00 00 8D 85 B4 00 00 00 50 8D 85 B4 01 00 00 50 6A 00 FF 95 18 61 00 00 5D 6A FF FF 95 10 61 00 00 44 65 62 75 67 67 65 72 20 6F 72 20 74 6F 6F 6C 20 66 6F 72 20 6D 6F 6E 69 74 6F 72 69 6E 67 20 64 65 74 65 63 74 65 64 21 21 21 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule ARM_Protector_v0_1_by_SMoKE
{
strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4  }

condition:
		$a0 at entrypoint
}
	
	
rule Fusion_V1_0____jaNooNi
{
strings:
		$a0 = { 68 04 30 40 00 68 04 30 40 00 E8 09 03 00 00 68 04 30 40 00 E8 C7 02 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__MinGW_GCC_2_x______Anorganix
{
strings:
		$a0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_v0_51
{
strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08  }

condition:
		$a0 at entrypoint
}
	
	
rule NeoLite_v2_0
{
strings:
		$a0 = { 9E 37 00 00 ?? ?? 48 ?? ?? ?? 6F 4C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 61  }
	$a1 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4E 65 6F 4C 69 74 65  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule RCryptor_v1_3___v1_4_____Vaska
{
strings:
		$a0 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_MSVC___DLL_Method_4_____emadicius
{
strings:
		$a0 = { 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C 85 F6 5F 5E 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule AINEXE_v2_30
{
strings:
		$a0 = { 0E 07 B9 ?? ?? BE ?? ?? 33 FF FC F3 A4 A1 ?? ?? 2D ?? ?? 8E D0 BC ?? ?? 8C D8  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___v6_0_SPx
{
strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 8B F0 8A ?? 3C 22  }
	$a1 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 6A 01 8B F0 FF 15  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule EXEJoiner_v1_0
{
strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 C6 00 5C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule VOB_ProtectCD
{
strings:
		$a0 = { 5F 81 EF ?? ?? ?? ?? BE ?? ?? 40 ?? 8B 87 ?? ?? ?? ?? 03 C6 57 56 8C A7 ?? ?? ?? ?? FF 10 89 87 ?? ?? ?? ?? 5E 5F  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_Basic_v5_0___v6_0
{
strings:
		$a0 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 ?? 00 00 00 30 ?? 00  }
	$a1 = { FF 25 ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? FF FF FF  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PeStubOEP_v1_x
{
strings:
		$a0 = { B8 ?? ?? ?? 00 FF E0  }
	$a1 = { E8 05 00 00 00 33 C0 40 48 C3 E8 05  }
	$a2 = { 90 33 C9 33 D2 B8 ?? ?? ?? 00 B9 FF  }
	$a3 = { 90 ?? 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint
}
	
	
rule PE_Protect_v0_9
{
strings:
		$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 ?? ?? ?? ?? 58 83 C0 07 C6 ?? C3  }
	$a1 = { E9 ?? 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 20 28 43 29 6F 70 79 72 69 67 68 74 20 62 79 20 43 48 52 69 53 54 4F 50 48 20 47 41 42 4C 45 52 20 69 6E 20 31 39 39 38 21 0D 0A 52 65 67 69 73 74 65 72 65 64 20 74 6F 20 3A 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule EXECryptor_v1_5_3
{
strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 ?? ?? 00 31 C0 89 41 14 89 41 18 80 A1 C1 00 00 00 FE C3 31 C0 64 FF 30 64 89 20 CC C3  }

condition:
		$a0 at entrypoint
}
	
	
rule UltraPro_V1_0____SafeNet_____Sign_By_fly
{
strings:
		$a0 = { A1 ?? ?? ?? ?? 85 C0 0F 85 3B 06 00 00 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15  }

condition:
		$a0 at entrypoint
}
	
	
rule NsPacK_V3_7____LiuXingPing_____Sign_By_fly
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 80 39 01 0F ?? ?? ?? 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE_v2_00c
{
strings:
		$a0 = { 50 B8 ?? ?? BA ?? ?? 3B C4 73 ?? 8B C4 2D ?? ?? 25 ?? ?? 8B F8 B9 ?? ?? BE ?? ?? FC  }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtect_vx_x
{
strings:
		$a0 = { 60 ?? ?? ?? ?? ?? 90 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 DD  }

condition:
		$a0 at entrypoint
}
	
	
rule Password_Protector__c__MiniSoft_1992
{
strings:
		$a0 = { 06 0E 0E 07 1F E8 00 00 5B 83 EB 08 BA 27 01 03 D3 E8 3C 02 BA EA  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____Borland_Delphi___Microsoft_Visual_C_____ASM_
{
strings:
		$a0 = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0___7_0_
{
strings:
		$a0 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? 00 EB 02 CD 20 03 D3 8D 35 F4 00 00 00 EB 01 35 EB 01 88 80 CA 7C 80 F3 74 8B 38 EB 02 AC BA 03 DB E8 01 00 00 00 A5 5B C1 C2 0B 81 C7 DA 10 0A 4E EB 01 08 2B D1 83 EF 14 EB 02 CD 20 33 D3 83 EF 27  }
	$a1 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? ?? EB 02 CD 20 03 D3 8D 35 F4 00  }
	$a2 = { 87 FE E8 02 00 00 00 98 CC 5F BB 80 ?? ?? 00 EB 02 CD 20 68 F4 00 00 00 E8 01 00 00 00 E3  }
	$a3 = { F7 D8 40 49 EB 02 E0 0A 8D 35 80 ?? ?? ?? 0F B6 C2 EB 01 9C 8D 1D F4 00 00 00 EB 01 3C 80  }
	$a4 = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? A7 BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint or $a4 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt
{
strings:
		$a0 = { E8 01 00 00 00 ?? ?? E8 ?? 00 00 00  }
	$a1 = { EB 01 ?? EB 02 ?? ?? ?? 80 ?? ?? 00  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ACProtect_v1_90g____Risco_software_Inc_
{
strings:
		$a0 = { 60 0F 87 02 00 00 00 1B F8 E8 01 00 00 00 73 83 04 24 06 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Nakedbind_V1_0____nakedcrew
{
strings:
		$a0 = { 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B 4D 5A 74 08 81 EB 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Morphine_v1_2__DLL_
{
strings:
		$a0 = { 00 00 00 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 5B ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PEX_v0_99
{
strings:
		$a0 = { E9 F5 ?? ?? ?? 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4  }
	$a1 = { 60 E8 01 ?? ?? ?? ?? 83 C4 04 E8 01 ?? ?? ?? ?? 5D 81  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule VProtector_V1_0D____vcasm
{
strings:
		$a0 = { 55 8B EC 6A FF 68 CA 31 41 00 68 06 32 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50  }

condition:
		$a0 at entrypoint
}
	
	
rule Crunch_PE_v3_0_x_x
{
strings:
		$a0 = { EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? FF 74  }

condition:
		$a0 at entrypoint
}
	
	
rule Shegerd_Dongle_V4_78____MS_Co______Sign_By_fly
{
strings:
		$a0 = { E8 32 00 00 00 B8 ?? ?? ?? ?? 8B 18 C1 CB 05 89 DA 36 8B 4C 24 0C  }

condition:
		$a0 at entrypoint
}
	
	
rule PocketPC_SHA
{
strings:
		$a0 = { 86 2F 96 2F A6 2F B6 2F 22 4F 43 68 53 6B 63 6A 73 69 F0 7F 0B D0 0B 40 09 00 09 D0 B3 65 A3 66 93 67 0B 40 83 64 03 64 04 D0 0B 40 09 00 10 7F 26 4F F6 6B F6 6A F6 69 0B 00 F6 68 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 22 4F F0 7F 0A D0 06 D4 06 D5 0B 40 09  }

condition:
		$a0 at entrypoint
}
	
	
rule Ding_Boy_s_PE_lock_v0_07
{
strings:
		$a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 23 35 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PocketPC_ARM
{
strings:
		$a0 = { F0 40 2D E9 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 03 70 A0 E1 ?? 00 00 EB 07 30 A0 E1 06 20 A0 E1 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB F0 40 BD E8 ?? 00 00 EA ?? 40 2D E9 ?? ?? 9F E5 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 9F E5 00 ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule ENIGMA_Protector_V1_12___Sukhov_Vladimir
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 C5 FA 81 ED ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31  }

condition:
		$a0 at entrypoint
}
	
	
rule iPBProtect_v0_1_3
{
strings:
		$a0 = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 FA 33 DB 89 5D F8 6A 02 EB 01 F8 58 5F 5E 5B 64 8B 25 00 00 00 00 64 8F 05 00 00 00 00 58 58 58 5D 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 C2 50 00 EB D3 5B F3 68 89 5C 24 48 5C 24 58 FF 8D 5C 24 58 5B 83 C3 4C 75 F4 5A 8D 71 78 75 09 81 F3 EB FF 52 BA 01 00 83 EB FC 4A FF 71 0F 75 19 8B 5C 24 00 00 81 33 50 53 8B 1B 0F FF C6 75 1B 81 F3 EB 87 1C 24 8B 8B 04 24 83 EC FC EB 01 E8 83 EC FC E9 E7 00 00 00 58 EB FF F0 EB FF C0 83 E8 FD EB FF 30 E8 C9 00 00 00 89 E0 EB FF D0 EB FF 71 0F 83 C0 01 EB FF 70 F0 71 EE EB FA EB 83 C0 14 EB FF 70 ED 71 EB EB FA FF 83 C0 FC EB FF 70 ED 71 EB EB FA 0F 83 C0 F8 EB FF 70 ED 71 EB EB FA FF 83 C0 18 EB FF 70  }

condition:
		$a0 at entrypoint
}
	
	
rule App_Protector____Silent_Team
{
strings:
		$a0 = { E9 97 00 00 00 0D 0A 53 69 6C 65 6E 74 20 54 65 61 6D 20 41 70 70 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 72 65 61 74 65 64 20 62 79 20 53 69 6C 65 6E 74 20 53 6F 66 74 77 61 72 65 0D 0A 54 68 65 6E 6B 7A 20 74 6F 20 44 6F 63 68 74 6F 72 20 58 0D 0A 0D 0A  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v4_00_0053____Silicon_Realms_Toolworks
{
strings:
		$a0 = { 55 8B EC 6A FF 68 20 8B 4B 00 68 80 E4 48 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4B 00 33 D2 8A D4 89 15 A4 A1 4B 00 8B C8 81 E1 FF 00 00 00 89 0D A0 A1 4B 00 C1 E1 08 03 CA 89 0D 9C A1 4B 00 C1 E8 10 A3 98 A1  }

condition:
		$a0 at entrypoint
}
	
	
rule N_Joiner_0_1__Asm_Version_____NEX
{
strings:
		$a0 = { 6A 00 68 00 14 40 00 68 00 10 40 00 6A 00 E8 14 00 00 00 6A 00 E8 13 00 00 00 CC FF 25 AC 12 40 00 FF 25 B0 12 40 00 FF 25 B4 12 40 00 FF 25 B8 12 40 00 FF 25 BC 12 40 00 FF 25 C0 12 40 00 FF 25 C4 12 40 00 FF 25 C8 12 40 00 FF 25 CC 12 40 00 FF 25 D0 12 40 00 FF 25 D4 12 40 00 FF 25 D8 12 40 00 FF 25 DC 12 40 00 FF 25 E4 12 40 00 FF 25 EC 12 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule SimplePack_V1_1X_V1_2X__Method1_____bagie_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA BD ?? ?? ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_20b1
{
strings:
		$a0 = { 55 8B EC 6A FF 68 30 12 41 00 68 A4 A5 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Copy_Protector_v2_0
{
strings:
		$a0 = { 2E A2 ?? ?? 53 51 52 1E 06 B4 ?? 1E 0E 1F BA ?? ?? CD 21 1F  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v1_90
{
strings:
		$a0 = { 55 8B EC 6A FF 68 10 F2 40 00 68 64 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule MingWin32_GCC_V3_X_____Sign_By_fly
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? 40 00 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_Protector_v1_0x__1_
{
strings:
		$a0 = { EB EC ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07  }

condition:
		$a0 at entrypoint
}
	
	
rule Blade_Joiner_v1_5
{
strings:
		$a0 = { 55 8B EC 81 C4 E4 FE FF FF 53 56 57 33 C0 89 45 F0 89 85  }

condition:
		$a0 at entrypoint
}
	
	
rule mkfpack__APlib______llydd___Sign_By_Celta68___20080131
{
strings:
		$a0 = { E8 00 00 00 00 5B 81 EB 05 00 00 00 8B 93 9F 08 00 00 53 6A ?? 68 ?? ?? ?? ?? 52 6A 00 FF 93 32 08 00 00 5B 8B F0 8B BB 9B 08 00 00 03 FB 56 57 E8 86 08 00 00 83 C4 08 8D 93 BB 08 00 00 52 53 FF E6  }

condition:
		$a0 at entrypoint
}
	
	
rule TPPpack____clane
{
strings:
		$a0 = { E8 00 00 00 00 5D 81 ED F5 8F 40 00 60 33 ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule VProtector_V1_0A____vcasm
{
strings:
		$a0 = { 55 8B EC 6A FF 68 8A 8E 40 00 68 C6 8E 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50  }

condition:
		$a0 at entrypoint
}
	
	
rule MPRESS_V0_97_V0_99____MATCODE_Software_____Sign_By_fly___20080416
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 05 49 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 3B FE 73 28 AC 0A C0 74 23 8A C8 24 3F C1 E0 10 66 AD 80 E1 40 74 0F 8B D6 8B CF 03 F0 E8 60 00 00 00 03 F8 EB D8 8B C8 F3 A4 EB D2 5E 5A 83 EA 05 2B C9 3B CA 73 26 8B D9 AC 41 24 FE 3C E8 75 F2 43 83 C1 04 AD 0B C0 78 06 3B C2 73 E5 EB 06 03 C3 78 DF 03 C2 2B C3 89 46 FC EB D6 E8 00 00 00 00 5F 81 C7 69 FF FF FF B0 E9 AA B8 45 01 00 00 AB E8 00 00 00 00 58 05 A3 00 00 00 E9 93 00 00 00 53 56 57 8B F9 8B F2 8B DA 03 D8 51 55 33 C0 8B EB 8B DE 2B D2 2B C9 EB 4F 3B DD 73 6C 2B C9 66 8B 03 8D 5B 02 8A CC 80 E4 0F 0B C0 75 02 B4 10 C0 E9 04 80 C1 03 80 F9 12 72 19 8A 0B 66 83 C1 12 43 66 81 F9 11 01 72 0B 66 8B 0B 81 C1 11 01 00 00 43 43 8B F7 2B F0 F3 A4 12 D2 74 0A 72 B9 8A 03 43 88 07 47 EB F2 3B DD 73 1D 0A 13 F9 74 03 43 EB E6 8B 43 01 89 07 8B 43 05 89 47 04 8D 5B 09 8D 7F 08 33 C0 EB DF 5D 8B C7 59 2B C1 5F 5E 5B C3 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_Modified_Stub_c____Farb_rausch_Consumer_Consulting
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 E8 00 00 00 00 5B 83 C3 66 A4 FF D3 73 FB 31 C9 FF D3 73 14 31 C0 FF D3 73 1D 41 B0 10 FF D3 10 C0 73 FA 75 3C AA EB E2 E8 4A 00 00 00 49 E2 10 E8 40 00 00 00 EB 28 AC D1 E8 74 45 11 C9 EB 1C 91 48  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_V5_20_Beta1____Silicon_Realms_Toolworks_____Sign_By_fly___20080214
{
strings:
		$a0 = { E8 8E 3F 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 9E 16 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 F5 14 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 86 14 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? ?? 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 07 13 00 00 59 89 7D FC FF 75 08 E8 AC 47 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 7C D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 C7 F9 FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 AD 11 00 00 59 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule MPRESS_V1_01____MATCODE_Software_____Sign_By_fly___20080730
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 05 ?? ?? ?? ?? 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 8B D6 8B CF E8 56 00 00 00 5E 5A 83 EA 05 2B C9 3B CA 73 26 8B D9 AC 41 24 FE 3C E8 75 F2 43 83 C1 04 AD 0B C0 78 06 3B C2 73 E5 EB 06 03 C3 78 DF 03 C2 2B C3 89 46 FC EB D6 E8 00 00 00 00 5F 81 C7 8D FF FF FF B0 E9 AA B8 B2 02 00 00 AB E8 00 00 00 00 58 05 34 02 00 00 E9 24 02 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PLINK86_1984__1985
{
strings:
		$a0 = { FA 8C C7 8C D6 8B CC BA ?? ?? 8E C2 26  }

condition:
		$a0 at entrypoint
}
	
	
rule Themida_1_0_x_x___1_8_0_0__compressed_engine_____Oreans_Technologies
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 5A ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 5A ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 AF 01  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___vx_x
{
strings:
		$a0 = { 55 8B EC 56 57 BF ?? ?? ?? ?? 8B ?? ?? 3B F7 0F  }
	$a1 = { 53 55 56 8B ?? ?? ?? 85 F6 57 B8 ?? ?? ?? ?? 75 ?? 8B ?? ?? ?? ?? ?? 85 C9 75 ?? 33 C0 5F 5E 5D 5B C2  }
	$a2 = { 55 8B EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 83 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule Armadillo_v1_9x
{
strings:
		$a0 = { 55 8B EC 6A FF 68 98 ?? ?? ?? 68 10 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15  }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDote_1_4_SE____SIS_Team
{
strings:
		$a0 = { 68 90 03 00 00 E8 C6 FD FF FF 68 90 03 00 00 E8 BC FD FF FF 68 90 03 00 00 E8 B2 FD FF FF 50 E8 AC FD FF FF 50 E8 A6 FD FF FF 68 69 D6 00 00 E8 9C FD FF FF 50 E8 96 FD FF FF 50 E8 90 FD FF FF 83 C4 20 E8 78 FF FF FF 84 C0 74 4F 68 04 01 00 00 68 10 22 60 00 6A 00 FF 15 08 10 60 00 68 90 03 00 00 E8 68 FD FF FF 68 69 D6 00 00 E8 5E FD FF FF 50 E8 58 FD FF FF 50 E8 52 FD FF FF E8 DD FE FF FF 50 68 A4 10 60 00 68 94 10 60 00 68 10 22 60 00 E8 58 FD FF FF 83 C4 20 33 C0 C2 10 00 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_00b2_2_00b3
{
strings:
		$a0 = { 55 8B EC 6A FF 68 00 F2 40 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Sentinel_Keys_Shell_V1_1_3_0_Dongle_Driver_V7_4_0_____SafeNet_Inc______Sign_By_fly___20090524
{
strings:
		$a0 = { 55 8B EC 81 EC 0C 01 00 00 53 56 57 C7 85 04 FF FF FF 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 F8 00 00 00 00 C7 85 08 FF FF FF 00 00 00 00 C7 45 E4 04 00 00 00 83 3D ?? ?? ?? ?? 00 74 05 E9 ?? ?? 00 00 A1 ?? ?? ?? ?? 83 C0 01  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Necropolis_1963
{
strings:
		$a0 = { B4 30 CD 21 3C 03 ?? ?? B8 00 12 CD 2F 3C FF B8 ?? ?? ?? ?? B4 4A BB 40 01 CD 21 ?? ?? FA 0E 17 BC ?? ?? E8 ?? ?? FB A1 ?? ?? 0B C0  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE_v1_50__1_
{
strings:
		$a0 = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 ?? BA ?? ?? CD 21 B8 ?? ?? CD 21  }

condition:
		$a0 at entrypoint
}
	
	
rule WinZip_32_bit_SFX_v6_x_module
{
strings:
		$a0 = { FF 15 ?? ?? ?? 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 38 08 74 06 40 80 38 00 75 F6 80 38 00 74 01 40 33 C9 ?? ?? ?? ?? FF 15  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_V5_40_V5_42____Silicon_Realms_Toolworks_____Sign_By_fly___20080214
{
strings:
		$a0 = { E8 93 3E 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 B4 1F 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 AF 1D 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 40 1D 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? ?? 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 C1 1B 00 00 59 89 7D FC FF 75 08 E8 B1 46 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 86 D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 C4 FA FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 67 1A 00 00 59 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule CrackStop_v1_01__c__Stefan_Esser_1997
{
strings:
		$a0 = { B4 48 BB FF FF B9 EB 27 8B EC CD 21 FA FC  }

condition:
		$a0 at entrypoint
}
	
	
rule ACProtect_v1_41
{
strings:
		$a0 = { 60 76 03 77 01 7B 74 03 75 01 78 47 87 EE E8 01 00 00 00 76 83 C4 04 85 EE EB 01 7F 85 F2 EB 01 79 0F 86 01 00 00 00 FC EB 01 78 79 02 87 F2 61 51 8F 05 19 38 01 01 60 EB 01 E9 E9 01 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule nPack_V1_1_275_2006_Beta____NEOx_____Sign_By_fly___200800212
{
strings:
		$a0 = { 55 8B EC 51 51 56 57 BE ?? ?? ?? ?? 8D 7D F8 66 A5 A4 BE ?? ?? ?? ?? 8D 7D FC 8D 45 FC 66 A5 50 8D 45 F8 50 A4 FF 15 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? 5F 5E 75 05 E8 02 00 00 00 C9 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8 1A 02 00 00 E8 CA 06 00 00 E8 19 06 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 56 57 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 8B F8 68 ?? ?? ?? ?? 57 FF D6 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 5F A3 ?? ?? ?? ?? 5E C3  }

condition:
		$a0 at entrypoint
}
	
	
rule SimplePack_V1_0X____bagie_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA 6A 00 FF 93 ?? ?? 00 00 89 C5 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 8B 86 88 00 00 00 09 C0  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPR_Stripper_v2_x_unpacked
{
strings:
		$a0 = { BB ?? ?? ?? ?? E9 ?? ?? ?? ?? 60 9C FC BF ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 AA 9D 61 C3 55 8B EC  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v3_01__v3_05
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 33 C9 75 02 EB 15 EB 33 C9 75 18 7A 0C 70 0E EB 0D E8 72 0E 79 F1 FF 15 00 79 09 74 F0 EB 87 DB 7A F0 A0 33 61 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 9C 33 C0 E8 09 00 00 00 E8 E8 23 00 00 00 7A 23 A0 8B 04 24 EB 03 7A 29 E9 C6 00 90 C3 E8 70 F0 87 D2 71 07 E9 00 40 8B DB 7A 11 EB 08 E9 EB F7 EB C3 E8 7A E9 70 DA 7B D1 71 F3 E9 7B  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_Borland_Delphi_6_0_7_0_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 53 8B D8 33 C0 A3 00 00 00 00 6A 00 E8 00 00 00 FF A3 00 00 00 00 A1 00 00 00 00 A3 00 00 00 00 33 C0 A3 00 00 00 00 33 C0 A3 00 00 00 00 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_V0_98_Special_Build____forgot___heXer_____Sign_By_fly
{
strings:
		$a0 = { E9 99 D7 FF FF 00 00 00 ?? ?? ?? ?? AA ?? ?? 00 00 00 00 00 00 00 00 00 CA  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__FSG_1_31______Anorganix
{
strings:
		$a0 = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Watcom_C_C__
{
strings:
		$a0 = { E9 ?? ?? 00 00 03 10 40 00 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 69 6D 65 20 73 79 73 74 65 6D 2E 20 28 63 29 20 43 6F 70 79 72 69 67 68 74 20 62 79 20 57 41 54 43 4F 4D 20 49 6E 74 65 72 6E 61 74 69 6F 6E 61 6C 20 43 6F 72 70 2E 20 31 39 38 38 2D 31 39 39 35 2E 20 41 6C 6C 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 2E 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule EXELOCK_666_1_5
{
strings:
		$a0 = { BA ?? ?? BF ?? ?? EB ?? EA ?? ?? ?? ?? 79 ?? 7F ?? 7E ?? 1C ?? 48 78 ?? E3 ?? 45 14 ?? 5A E9  }

condition:
		$a0 at entrypoint
}
	
	
rule UG2002_Cruncher_v0_3b3
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? E8 0D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Petite_1_2_____c_1998_Ian_Luck
{
strings:
		$a0 = { 66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 09 00 0A 00 0B 00 0D 00 0F 00 11 00 13 00 17 00 1B 00 1F 00 23 00 2B 00 33 00 3B 00 43 00 53 00 63 00 73 00 83 00 A3 00 C3 00 E3 00 02 01 00 00 00 00 00 00 00 00 00 00 00 00 01 01 01 01 02 02 02  }

condition:
		$a0 at entrypoint
}
	
	
rule Anskya_Binder_v1_1____Anskya
{
strings:
		$a0 = { BE ?? ?? ?? 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11  }

condition:
		$a0 at entrypoint
}
	
	
rule PeX_v0_99__Eng_____bart_CrackPl
{
strings:
		$a0 = { E9 F5 00 00 00 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4  }

condition:
		$a0 at entrypoint
}
	
	
rule Pe123__v2006_4_12
{
strings:
		$a0 = { 8B C0 60 9C E8 01 00 00 00 C3 53 E8 72 00 00 00 50 E8 1C 03 00 00 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 8B 7D 0C 8B 75 08 F3 A4 61 5D C2 0C 00 E8 00 00 00 00 58 83 E8 05 C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B  }

condition:
		$a0 at entrypoint
}
	
	
rule PEBundle_v2_0b5___v2_3
{
strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 01 AD ?? ?? ?? ?? 01 AD  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___v8_0
{
strings:
		$a0 = { E8 ?? ?? ?? ?? E9 ?? ?? FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_52_beta2
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? B0 ?? ?? ?? ?? 68 60 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 24  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__GRUNT_4_Family
{
strings:
		$a0 = { E8 1C 00 8D 9E 41 01 40 3E 8B 96 14 03 B9 EA 00 87 DB F7 D0 31 17 83 C3 02 E2 F7 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Themida_1_8_x_x____Oreans_Technologies
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D 37 ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE_Stealth_V2_7X____WebtoolMaster____Sign_By_fly___20080109
{
strings:
		$a0 = { EB 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 E8 00 00 00 00 5D 81 ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? ?? ?? 04 ?? ?? 01 EB 05 ?? ?? ?? ?? ?? EB 00 EB 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Feokt
{
strings:
		$a0 = { 89 25 A8 11 40 00 BF ?? ?? ?? 00 31 C0 B9 ?? ?? ?? 00 29 F9 FC F3 AA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 BE ?? ?? 40 00 BF  }

condition:
		$a0 at entrypoint
}
	
	
rule PowerBASIC_CC_3_0x
{
strings:
		$a0 = { 55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? ?? 00 04 00 0F 85  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__DxPack_1_0______Anorganix
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Kuku_886
{
strings:
		$a0 = { 06 1E 50 8C C8 8E D8 BA 70 03 B8 24 25 CD 21 ?? ?? ?? ?? ?? 90 B4 2F CD 21 53  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_Protector_v1_0x__2_
{
strings:
		$a0 = { EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB  }

condition:
		$a0 at entrypoint
}
	
	
rule IcebergLock_Protector_V3_10_1_41____Iceberg_Software_Lab_____Sign_By_fly___20081209
{
strings:
		$a0 = { E8 D7 FF FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 8B EC 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB F8 5D C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8B EC 83 C4 ?? B8 A8 ?? ?? ?? E8 94 EC FD FF E8 43 DE FF FF B8 58 ?? ?? ?? E8 71 FE FF FF E8 F4 CD FD FF  }

condition:
		$a0 at entrypoint
}
	
	
rule PEiD_Bundle_v1_00___v1_01_____BoB___BobSoft
{
strings:
		$a0 = { 60 E8 ?? 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A  }

condition:
		$a0 at entrypoint
}
	
	
rule SPLayer_v0_08
{
strings:
		$a0 = { 8D 40 00 B9 ?? ?? ?? ?? 6A ?? 58 C0 0C ?? ?? 48 ?? ?? 66 13 F0 91 3B D9 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_15_V1_17__LZMA_4_30_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 83 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB 14  }

condition:
		$a0 at entrypoint
}
	
	
rule UPXShit_0_06
{
strings:
		$a0 = { B8 ?? ?? 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_v0_60
{
strings:
		$a0 = { E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE_v1_12__v1_15__v1_20__2_
{
strings:
		$a0 = { B8 ?? ?? BA ?? ?? 3B C4 73  }

condition:
		$a0 at entrypoint
}
	
	
rule Sentinel_Dongle_Shell____SafeNet_Inc______Sign_By_fly___20090508
{
strings:
		$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 C7 85 04 FF FF FF 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 F8 00 00 00 00 C7 85 08 FF FF FF 00 00 00 00 C7 45 E4 04 00 00 00 83 ?? ?? ?? ?? ?? 00 74 05 E9 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 01 A3 ?? ?? ?? ?? 83 F4 00 7B 00 8D 80 ?? ?? ?? ?? 8D 80 ?? ?? ?? ?? 76 0F ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 EC 08 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule NoodleCrypt_v2_0
{
strings:
		$a0 = { EB 01 9A E8 ?? 00 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01  }
	$a1 = { EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PESpin_V0_3____cyberbob_____Sign_By_fly___20080312
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 CB 2C 40 00 8B 42 3C 03 C2 89 85 D5 2C 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D E9 2C 40 00 53 8F 85 B6 2B 40 00 BB ?? 00 00 00 B9 75 0A 00 00 8D BD 7E 2D 40 00 4F 30 1C 39 FE CB E2 F9 68 3C 01 00 00 59 8D BD B6 36 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 1F 53 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D DC 2C 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_2_X____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { E8 0E 00 00 00 33 C0 8B 54 24 0C 83 82 B8 00 00 00 0D C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE_v1_14__v1_15__v1_20__3_
{
strings:
		$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B ?? ?? ?? 72 ?? B4 09 BA ?? 01 CD 21 CD 20 4E 6F  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Sonik_Youth
{
strings:
		$a0 = { 8A 16 02 00 8A 07 32 C2 88 07 43 FE C2 81 FB  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Compiler
{
strings:
		$a0 = { 8C C3 83 C3 10 2E 01 1E ?? 02 2E 03 1E ?? 02 53 1E  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_V0_21____Dwing_____Sign_By_fly___20080321
{
strings:
		$a0 = { BE ?? ?? ?? ?? AD 8B F8 6A 04 95 A5 33 C0 AB 48 AB F7 D8 59 F3 AB C1 E0 0A ?? ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF ?? ?? ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 01 67 E3 29 8B D7 2B 55 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 56 08 33 C9 E9 07 01 00 00 8B 5D 0C 83 C2 30 FF 16 73 53 83 C2 30 FF 16 72 1B 83 C2 30 FF 16 72 2B 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 45 0C B1 80 8A 00 EB CF 83 C2 60 FF 16 87 5D 10 73 0D 83 C2 30 FF 16 87 5D 14 73 03 87 5D 18 3C 07 B0 08 72 02 B0 0B 50 53 8D 95 7C 07 00 00 FF 56 0C 5B 91 E9 9C 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule DxPack_V0_86____Dxd_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 06 10 40 00 2B BD 94 12 40 00 81 EF 06 00 00 00 83 BD 14 13 40 00 01 0F 84 2F 01 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_12_V1_14__aPlib_0_43_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF EB 0F FF ?? ?? ?? FF ?? ?? ?? D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB  }

condition:
		$a0 at entrypoint
}
	
	
rule MASM32
{
strings:
		$a0 = { 6A ?? 68 00 30 40 00 68 ?? 30 40 00 6A 00 E8 07 00 00 00 6A 00 E8 06 00 00 00 FF 25 08 20  }

condition:
		$a0 at entrypoint
}
	
	
rule WinZip_Self_Extractor_2_2_personal_edition____WinZip_Computing
{
strings:
		$a0 = { 53 FF 15 58 70 40 00 B3 22 38 18 74 03 80 C3 FE 40 33 D2 8A 08 3A CA 74 10 3A CB 74 07 40 8A 08 3A CA 75 F5 38 10 74 01 40 52 50 52 52 FF 15 5C 70 40 00 50 E8 15 FB FF FF 50 FF 15 8C 70 40 00 5B  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Phoenix_927
{
strings:
		$a0 = { E8 00 00 5E 81 C6 ?? ?? BF 00 01 B9 04 00 F3 A4 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule marcrypt
{
strings:
		$a0 = { 60 75 03 74 01 E8 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 09 C0 74 06 E8 00 00 00 00 C3 75 0A 74 08 39 41 48 74 61 50 53 C3 50 8B C4 58 74 03 75 01 E9 B8 00 ?? 40 00 B9 ?? ?? ?? 00 8B 10 81 F2 EA AF AC 0C 89 10 83 C0 04 49 09 C9 75 EE 75 03 74 01 E8 61 EB 17 01 D3 58 EB 21 40 C1 C0 02 0D FF 00 FF 00 09 C0 50 74 EF 75 ED 74 EF EB F7 83 F8 00 74 E8 99 F7 F1 39 CA 74 E1 C3 75 0A 74 08  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___v5_0_DLL
{
strings:
		$a0 = { 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 8B ?? 24 0C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_1_3_3_2____Obsidium_Software
{
strings:
		$a0 = { EB 01 ?? E8 2B 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 02 ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 3B 27 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_00__Eng_____dulek_xt
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38  }

condition:
		$a0 at entrypoint
}
	
	
rule NoobyProtect_V1_1_4_0____Nooby_____Sign_By_fly___20090201
{
strings:
		$a0 = { E9 ?? 00 00 00 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 53 45 20 31 2E 31 2E 34 2E 30  }

condition:
		$a0 at entrypoint
}
	
	
rule PECompact_v2_0_beta____Jeremy_Collake
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90  }

condition:
		$a0 at entrypoint
}
	
	
rule APatch_GUI_v1_1
{
strings:
		$a0 = { 52 31 C0 E8 FF FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule TMT_Pascal_v0_40
{
strings:
		$a0 = { 0E 1F 06 8C 06 ?? ?? 26 A1 ?? ?? A3 ?? ?? 8E C0 66 33 FF 66 33 C9  }

condition:
		$a0 at entrypoint
}
	
	
rule Nullsoft_PIMP_Install_System_v1_x
{
strings:
		$a0 = { 83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Enigma_Protector_V1_31_Build_20070615_Dll____Sukhov_Vladimir___Serge_N__Markin_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 81 ED ?? ?? ?? ?? E9 49 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 8A 84 24 28 00 00 00 80 F8 01 0F 84 07 00 00 00 B8 ?? ?? ?? ?? FF E0 E9 04 00 00 00 ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 81 C0 ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 30 10 40 49 0F 85 F6 FF FF FF E9 04 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_2_90_rule__LZMA_____Markus_Oberhumer__Laszlo_Molnar___John_Reiser
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90  }
	$a1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Vx__Necropolis
{
strings:
		$a0 = { 50 FC AD 33 C2 AB 8B D0 E2 F8  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v1_08_x
{
strings:
		$a0 = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 00 BB 10 6A 44 00 03 DD 2B 9D 2A  }

condition:
		$a0 at entrypoint
}
	
	
rule UPXFreak_v0_1__Borland_Delphi_____HMX0101
{
strings:
		$a0 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 34 50 45 00 ?? ?? ?? 00 FF FF 00 00 ?? 24 ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 40 00 00 C0 00 00 ?? ?? ?? ?? 00 00 ?? 00 00 00 ?? 1E ?? 00 ?? F7 ?? 00 A6 4E 43 00 ?? 56 ?? 00 AD D1 42 00 ?? F7 ?? 00 A1 D2 42 00 ?? 56 ?? 00 0B 4D 43 00 ?? F7 ?? 00 ?? F7 ?? 00 ?? 56 ?? 00 ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? 77 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 77 ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Fuck_n_Joy_v1_0c____UsAr
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED D8 05 40 00 FF 74 24 20 E8 8C 02 00 00 0B C0 0F 84 2C 01 00 00 89 85 6C 08 40 00 8D 85 2F 08 40 00 50 FF B5 6C 08 40 00 E8 EF 02 00 00 0B C0 0F 84 0C 01 00 00 89 85 3B 08 40 00 8D 85 3F 08 40 00 50 FF B5 6C 08 40 00 E8 CF 02 00 00 0B C0 0F 84 EC 00 00 00 89 85 4D 08 40 00 8D 85 51 08 40 00 50 FF B5 6C 08 40 00 E8 AF 02 00 00 0B C0 0F 84 CC 00 00 00 89 85 5C 08 40 00 8D 85 67 07 40 00 E8 7B 02 00 00 8D B5 C4 07 40 00 56 6A 64 FF 95 74 07 40 00 46 80 3E 00 75 FA C7 06 74 6D 70 2E 83 C6 04 C7 06 65 78 65 00 8D 85 36 07 40 00 E8 4C 02 00 00 33 DB 53 53 6A 02 53 53 68 00 00 00 40 8D 85 C4 07 40 00 50 FF 95 74 07 40 00 89 85 78 07 40 00 8D 85 51 07 40 00 E8 21 02 00 00 6A 00 8D 85 7C 07 40 00 50 68 00 ?? ?? 00 8D 85 F2 09 40 00 50 FF  }

condition:
		$a0 at entrypoint
}
	
	
rule ExeShield_3_6____www_exeshield_com
{
strings:
		$a0 = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC E9 FB C8 4F 1B 22 7C B4 C8 0D BD 71 A9 C8 1F 5F B1 29 8F 11 73 8F 00 D1 88 87 A9 3F 4D 00 6C 3C BF C0 80 F7 AD 35 23 EB 84 82 6F  }

condition:
		$a0 at entrypoint
}
	
	
rule PESHiELD_v0_1b_MTE
{
strings:
		$a0 = { E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B9 1B 01 ?? ?? D1  }

condition:
		$a0 at entrypoint
}
	
	
rule WARNING____TROJAN____HuiGeZi
{
strings:
		$a0 = { 55 8B EC 81 C4 ?? FE FF FF 53 56 57 33 C0 89 85 ?? FE FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v2_000
{
strings:
		$a0 = { 60 E8 70 05 00 00 EB 4C  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v2_001
{
strings:
		$a0 = { 60 E8 72 05 00 00 EB 4C  }

condition:
		$a0 at entrypoint
}
	
	
rule _BJFnt_v1_3
{
strings:
		$a0 = { EB ?? 3A ?? ?? 1E EB ?? CD 20 9C EB ?? CD 20 EB ?? CD 20 60 EB  }

condition:
		$a0 at entrypoint
}
	
	
rule AVPACK_v1_20
{
strings:
		$a0 = { 50 1E 0E 1F 16 07 33 F6 8B FE B9 ?? ?? FC F3 A5 06 BB ?? ?? 53 CB  }

condition:
		$a0 at entrypoint
}
	
	
rule CICompress_v1_0
{
strings:
		$a0 = { 6A 04 68 00 10 00 00 FF 35 9C 14 40 00 6A 00 FF 15 38 10 40 00 A3 FC 10 40 00 97 BE 00 20 40 00 E8 71 00 00 00 3B 05 9C 14 40 00 75 61 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 C0 68 94 10 40 00 FF 15 2C 10 40 00 A3 F8 10 40 00 6A 00 68 F4 10 40 00 FF 35 9C 14 40 00 FF 35 FC 10 40 00 FF 35 F8 10 40 00 FF 15 34 10 40 00 FF 35 F8 10 40 00 FF 15 30 10 40 00 68 00 40 00 00 FF 35 9C 14 40 00 FF 35 FC 10 40 00 FF 15 3C 10 40 00 6A 00 FF 15 28 10 40 00 60 33 DB 33 C9 E8 7F 00 00 00 73 0A B1 08 E8 82 00 00 00 AA EB EF E8 6E 00 00 00 73 14 B1 04 E8 71 00 00 00 3C 00 74 EB 56 8B F7 2B F0 A4 5E EB D4 33 ED E8 51 00 00 00 72 10 B1 02 E8 54 00 00 00 3C 00 74 3B 8B E8 C1 C5 08 B1 08 E8 44 00 00 00 0B C5 50 33 ED E8 2E 00 00 00 72 0C B1 02 E8 31 00 00 00 8B E8 C1 C5 08  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_PECompact_1_4x_____emadicius
{
strings:
		$a0 = { EB 06 68 2E A8 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule ORiEN_V2_12____Fisun_A_V_
{
strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE CD 0D  }

condition:
		$a0 at entrypoint
}
	
	
rule SoftSentry_v2_11
{
strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 E9 50  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___v7_0__64_Bit_
{
strings:
		$a0 = { 41 00 00 00 00 00 00 00 63 00 00 00 00 00 ?? 00 ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 20 ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule EncryptPE_V2_2004_6_16_V2_2006_6_30____WFS_____Sign_By_fly
{
strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 7A 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_Delphi_v5_0_KOL
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF 8B C0 00 00 00 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_20__Eng_____dulek_xt_____MASM32___TASM32_
{
strings:
		$a0 = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE  }

condition:
		$a0 at entrypoint
}
	
	
rule GP_Install_v5_0_3_32
{
strings:
		$a0 = { 55 8B EC 33 C9 51 51 51 51 51 51 51 53 56 57 B8 C4 1C 41 00 E8 6B 3E FF FF 33 C0 55 68 76 20 41 00 64 FF 30 64 89 20 BA A0 47 41 00 33 C0 E8 31 0A FF FF 33 D2 A1 A0  }

condition:
		$a0 at entrypoint
}
	
	
rule RE_Crypt_v0_7x____Crudd_rule__RET___h1_
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 61 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B  }

condition:
		$a0 at entrypoint
}
	
	
rule QrYPt0r___by_NuTraL
{
strings:
		$a0 = { EB 00 E8 B5 00 00 00 E9 2E 01 00 00 64 FF 35 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 89 25 00 00 00 00 8B 44 24 04  }

condition:
		$a0 at entrypoint
}
	
	
rule Goats_Mutilator_V1_6____Goat__e0f
{
strings:
		$a0 = { E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____Borland_C___1999_
{
strings:
		$a0 = { EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9  }

condition:
		$a0 at entrypoint
}
	
	
rule bambam_V0_04____bedrock_____Sign_By_fly
{
strings:
		$a0 = { BF ?? ?? ?? ?? 83 C9 FF 33 C0 68 ?? ?? ?? ?? F2 AE F7 D1 49 51 68 ?? ?? ?? ?? E8 11 0A 00 00 83 C4 0C 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B F0 BF ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 49 BF ?? ?? ?? ?? 8B D1 68 ?? ?? ?? ?? C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA BF ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 49 51 68 ?? ?? ?? ?? E8 C0 09 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_2_rule___BJFNT_1_2______Anorganix
{
strings:
		$a0 = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PMODE_W_v_1_12__1_16__1_21__1_33_DOS_extender
{
strings:
		$a0 = { FC 16 07 BF ?? ?? 8B F7 57 B9 ?? ?? F3 A5 06 1E 07 1F 5F BE ?? ?? 06 0E A4  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_PE_Lock_NT_2_04_____emadicius
{
strings:
		$a0 = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 03 CD 20 EB EB 03 CD 20 03 61 9D 83 C4 04 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin_V0_7____cyberbob_____Sign_By_fly___20080312
{
strings:
		$a0 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 00 EB FB FF 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? EB 01 ?? 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 ?? EB FB ?? 83 04 24 0C C3  }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptor_v1_______Vaska
{
strings:
		$a0 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE_v1_20
{
strings:
		$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 09 BA ?? ?? CD 21 B4 4C CD 21  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Virtualization_Suite_V3_348_V3_350____Thinstall_Company_____Sign_By_fly___20080318
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 59 19 00 00 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 AC 00 00 00 E8 2C FF FF FF E9 ?? FF FF FF CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 C3 B9 08 00 00 00 E8 01 00 00 00 C3 33 C0 E8 E1 FF FF FF 13 C0 E2 F7 C3 33 C9 41 E8 D4 FF FF FF 13 C9 E8 CD FF FF FF 72 F2 C3 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Cryptic_2_0____Tughack
{
strings:
		$a0 = { B8 00 00 40 00 BB ?? ?? ?? 00 B9 00 10 00 00 BA ?? ?? ?? 00 03 D8 03 C8 03 D1 3B CA 74 06 80 31 ?? 41 EB F6 FF E3  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_C__
{
strings:
		$a0 = { A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76 05 2B CF FC F3 AA 59 5F  }

condition:
		$a0 at entrypoint
}
	
	
rule SDProtector_Basic_Pro_Edition_1_12____Randy_Li
{
strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 20 33 C0 89 41 04 89 41 08 89 41 0C 89 41 10 59 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 33 C0 64 FF 30 64 89 20 9C 80 4C 24 01 01 9D 90 90 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 64 8F 00 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 03 79 01 E8 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 7B 03 00 00 03 C8 74 C4 75 C2 E8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E2  }

condition:
		$a0 at entrypoint
}
	
	
rule XJ___XPAL____LiNSoN_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 44 53 56 57 66 9C  }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor_2_3_9_DLL__minimum_protection_
{
strings:
		$a0 = { 51 68 ?? ?? ?? ?? 87 2C 24 8B CD 5D 81 E1 ?? ?? ?? ?? E9 ?? ?? ?? 00 89 45 F8 51 68 ?? ?? ?? ?? 59 81 F1 ?? ?? ?? ?? 0B 0D ?? ?? ?? ?? 81 E9 ?? ?? ?? ?? E9 ?? ?? ?? 00 81 C2 ?? ?? ?? ?? E8 ?? ?? ?? 00 87 0C 24 59 51 64 8B 05 30 00 00 00 8B 40 0C 8B 40 0C E9 ?? ?? ?? 00 F7 D6 2B D5 E9 ?? ?? ?? 00 87 3C 24 8B CF 5F 87 14 24 1B CA E9 ?? ?? ?? 00 83 C4 08 68 ?? ?? ?? ?? E9 ?? ?? ?? 00 C3 E9 ?? ?? ?? 00 E9 ?? ?? ?? 00 50 8B C5 87 04 24 8B EC 51 0F 88 ?? ?? ?? 00 FF 05 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 0C 24 59 99 03 04 24 E9 ?? ?? ?? 00 C3 81 D5 ?? ?? ?? ?? 9C E9 ?? ?? ?? 00 81 FA ?? ?? ?? ?? E9 ?? ?? ?? 00 C1 C3 15 81 CB ?? ?? ?? ?? 81 F3 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 87  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_Basic_v6_0
{
strings:
		$a0 = { FF 25 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? FF FF FF ?? ?? ?? ?? ?? ?? 30  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__SK
{
strings:
		$a0 = { CD 20 B8 03 00 CD 10 51 E8 00 00 5E 83 EE 09  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_v1_03___v1_04_Modified
{
strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF  }

condition:
		$a0 at entrypoint
}
	
	
rule Dev_C___v5
{
strings:
		$a0 = { 55 89 E5 83 EC 14 6A ?? FF 15 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule CreateInstall_v2003_3_5
{
strings:
		$a0 = { 81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 40 00 8B F0 FF 15 D4 80 40 00 3D B7 00 00 00 75 0F 56 FF 15 B8 80 40 00 6A 02 FF 15 A4 80 40 00 33 DB E8 F2 FE FF FF 68 02 7F 00 00 89 1D 94 74 40 00 53 89 1D 98 74 40 00 FF 15 E4 80 40 00 50 FF 15 E0 80 40 00 8B 0D 00 50 40 00 E8 68 FF FF FF B9 40 0D 03 00 89 44 24 14 E8 5A FF FF FF 68 00 02 00 00 8B 2D D0 80 40 00 89 44 24 1C 8D 44 24 20 50 53 FF D5 8D 4C 24 1C 53 68 00 00 00 80 8B 3D CC 80 40 00 6A 03 53 6A 03 68 00 00 00 80 51 FF D7 8B F0 53 8D 44 24 14 8B 0D 00 50 40 00 8B 54 24 18 50 51 52 56 FF 15 C8 80 40 00 85 C0 0F 84 40 02 00 00 8B 15 00 50 40 00 3B 54 24 10 0F 85 30 02 00 00 6A FF A1 04 50 40 00 2B D0 8B 4C 24 18 03 C8 E8 9F FE FF FF 3B 05 10 50 40 00 0F 85 10 02 00 00 56 FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_0_0____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 22 EB 02 ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 47 26 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Packanoid_1_0____ackanoid
{
strings:
		$a0 = { BF 00 ?? 40 00 BE ?? ?? ?? 00 E8 9D 00 00 00 B8 ?? ?? ?? 00 8B 30 8B 78 04 BB ?? ?? ?? 00 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08 5E EB DB B9 ?? ?? 00 00 BE 00 ?? ?? 00 EB 01 00 BF ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___v7_0
{
strings:
		$a0 = { 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 89 65 ?? 8B F4 89 3E 56 FF 15 ?? ?? ?? ?? 8B 4E ?? 89 0D ?? ?? ?? ?? 8B 46 ?? A3  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___v5_0
{
strings:
		$a0 = { 55 8B EC 6A FF 68 68 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 53 56 57  }
	$a1 = { 55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 ?? 53 56 57 89 65 E8 FF 15 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 10 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule EXECryptor_v1_5_1_x
{
strings:
		$a0 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 C1 ?? ?? ?? FE C3 31 C0 64 FF 30 64 89 20 CC C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Virtualization_Suite_V3_0X____Thinstall_Company_____Sign_By_fly
{
strings:
		$a0 = { 9C 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 BA FE FF FF E9 ?? ?? ?? ?? CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA ?? ?? ?? ?? 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 ?? ?? ?? ?? E8 DF 00 00 00 73 1B 55 BD ?? ?? ?? ?? E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_1_31____dulek_xt
{
strings:
		$a0 = { BE ?? ?? ?? 00 BF ?? ?? ?? 00 BB ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80  }

condition:
		$a0 at entrypoint
}
	
	
rule DBPE_v2_33
{
strings:
		$a0 = { EB 20 ?? ?? 40 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83  }

condition:
		$a0 at entrypoint
}
	
	
rule PECompact_v1_84
{
strings:
		$a0 = { 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81  }

condition:
		$a0 at entrypoint
}
	
	
rule SDProtector_Pro_Edition_1_16____Randy_Li
{
strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 18 33 C0 89 41 04 89 41 08 89 41 0C 89 41 10 59 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 33 C0 64 FF 30 64 89 20 9C 80 4C 24 01 01 9D 90 90 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 64 8F 00 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 03 79 01 E8 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 93 03 00 00 03 C8 74 C4 75 C2 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_V0_3_V0_41____FEUERRADER_____Sign_By_fly
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 90 90 90 FF E0  }

condition:
		$a0 at entrypoint
}
	
	
rule PEBundle_v2_44
{
strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 83 BD  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Embedded_V2_609____Jitit_____Sign_By_fly
{
strings:
		$a0 = { E8 00 00 00 00 58 BB AD 19 00 00 2B C3 50 68 ?? ?? ?? ?? 68 B0 1C 00 00 68 80 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PKTINY_v1_0_with_TINYPROG_v3_8
{
strings:
		$a0 = { 2E C6 06 ?? ?? ?? 2E C6 06 ?? ?? ?? 2E C6 06 ?? ?? ?? E9 ?? ?? E8 ?? ?? 83  }

condition:
		$a0 at entrypoint
}
	
	
rule EXERefactor_V0_1____random_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC 81 EC 90 0B 00 00 53 56 57 E9 58 8C 01 00 55 53 43 41 54 49 4F 4E  }

condition:
		$a0 at entrypoint
}
	
	
rule WinRAR_32_bit_SFX_Module
{
strings:
		$a0 = { E9 ?? ?? 00 00 00 00 00 00 90 90 90 ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? FF  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_Basic_5_0___6_0_
{
strings:
		$a0 = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77  }

condition:
		$a0 at entrypoint
}
	
	
rule NTPacker_1_0____ErazerZ
{
strings:
		$a0 = { 55 8B EC 83 C4 E0 53 33 C0 89 45 E0 89 45 E4 89 45 E8 89 45 EC B8 ?? ?? 40 00 E8 ?? ?? FF FF 33 C0 55 68 ?? ?? 40 00 64 FF 30 64 89 20 8D 4D EC BA ?? ?? 40 00 A1 ?? ?? 40 00 E8 ?? FC FF FF 8B 55 EC B8 ?? ?? 40 00 E8 ?? ?? FF FF 8D 4D E8 BA ?? ?? 40 00 A1 ?? ?? 40 00 E8 ?? FE FF FF 8B 55 E8 B8 ?? ?? 40 00 E8 ?? ?? FF FF B8 ?? ?? 40 00 E8 ?? FB FF FF 8B D8 A1 ?? ?? 40 00 BA ?? ?? 40 00 E8 ?? ?? FF FF 75 26 8B D3 A1 ?? ?? 40 00 E8 ?? ?? FF FF 84 C0 75 2A 8D 55 E4 33 C0 E8 ?? ?? FF FF 8B 45 E4 8B D3 E8 ?? ?? FF FF EB 14 8D 55 E0 33 C0 E8 ?? ?? FF FF 8B 45 E0 8B D3 E8 ?? ?? FF FF 6A 00 E8 ?? ?? FF FF 33 C0 5A 59 59 64 89 10 68 ?? ?? 40 00 8D 45 E0 BA 04 00 00 00 E8 ?? ?? FF FF C3 E9 ?? ?? FF FF EB EB 5B E8 ?? ?? FF FF 00 00 00 FF FF FF FF 01 00 00 00 25 00 00 00 FF FF FF FF 01 00 00 00 5C 00 00 00 FF FF FF FF 06 00 00 00 53 45 52 56 45 52 00 00 FF FF FF FF 01 00 00 00 31  }

condition:
		$a0 at entrypoint
}
	
	
rule MinGW_v3_2_x__main_
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 E4 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 E4 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 00 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 F4 40 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 53 83 EC 24 C7 04 24 A0 11 40 00 E8 8D 07 00 00 83 EC 04 E8 85 02 00 00 C7 04 24 00 20 40 00 8B 15 10 20 40 00 8D 4D F8 C7 45 F8 00 00 00 00 89 4C 24 10 89 54 24 0C 8D 55 F4 89 54 24 08 C7 44 24 04 04 20 40 00 E8 02 07 00 00 A1 20 20 40 00 85 C0 74 76 A3 30 20 40 00 A1 F0 40 40 00 85 C0 74 1F 89 04 24 E8 C3 06 00 00 8B 1D 20 20 40 00 89 04 24 89 5C 24 04 E8 C1 06 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule SLVc0deProtector_v0_61____SLV
{
strings:
		$a0 = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 9D 11 40 00 8D 95 B4 11 40 00 E8 CB 2E 00 00 33 C0 F7 F0 69 8D B5 05 12 40 00 B9 5D 2E 00 00 8B FE AC  }

condition:
		$a0 at entrypoint
}
	
	
rule Dev_C___v4
{
strings:
		$a0 = { 55 89 E5 83 EC 08 83 C4 F4 6A ?? A1 ?? ?? ?? 00 FF D0 E8 ?? FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtect_v1_0
{
strings:
		$a0 = { 60 E8 01 ?? ?? ?? 90 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D  }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtect_v1_1
{
strings:
		$a0 = { 60 E9 ?? 04 ?? ?? E9 ?? ?? ?? ?? ?? ?? ?? EE  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_3_3____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B ?? 24 0C EB 01 ?? 83 ?? B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 27 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule SecuPack_v1_5
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 CC 3A 40 ?? E8 E0 FC FF FF 33 C0 55 68 EA 3C 40 ?? 64 FF 30 64 89 20 6A ?? 68 80 ?? ?? ?? 6A 03 6A ?? 6A 01 ?? ?? ?? 80  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__November_17_768
{
strings:
		$a0 = { E8 ?? ?? 5E 81 EE ?? ?? 50 33 C0 8E D8 80 3E ?? ?? ?? 0E 1F ?? ?? FC  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE_v1_14__v1_20
{
strings:
		$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 09 BA ?? ?? CD 21 CD 20  }

condition:
		$a0 at entrypoint
}
	
	
rule Crunch_PE_v2_0_x_x
{
strings:
		$a0 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 55 BB ?? ?? ?? ?? 03 DD 53 64 67 FF 36 ?? ?? 64 67 89 26  }

condition:
		$a0 at entrypoint
}
	
	
rule WATCOM_C_C___32_Run_Time_System_1988_1995
{
strings:
		$a0 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54  }

condition:
		$a0 at entrypoint
}
	
	
rule WATCOM_C_C___32_Run_Time_System_1988_1994
{
strings:
		$a0 = { FB 83 ?? ?? 89 E3 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 66 ?? ?? ?? 66 ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 29 C0 B4 30 CD 21  }

condition:
		$a0 at entrypoint
}
	
	
rule MinGW_GCC_v2_x
{
strings:
		$a0 = { 55 89 E5 E8 ?? ?? ?? ?? C9 C3 ?? ?? 45 58 45  }
	$a1 = { 55 89 E5 ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ASPack_v1_07b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 0B DE ?? 89 85 17 DE ?? ?? 80 BD 01 DE  }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor_2_3_9__compressed_resources_
{
strings:
		$a0 = { 51 68 ?? ?? ?? ?? 59 81 F1 12 3C CB 98 E9 53 2C 00 00 F7 D7 E9 EB 60 00 00 83 45 F8 02 E9 E3 36 00 00 F6 45 F8 20 0F 84 1E 21 00 00 55 E9 80 62 00 00 87 0C 24 8B E9 ?? ?? ?? ?? 00 00 23 C1 81 E9 ?? ?? ?? ?? 57 E9 ED 00 00 00 0F 88 ?? ?? ?? ?? E9 2C 0D 00 00 81 ED BB 43 CB 79 C1 E0 1C E9 9E 14 00 00 0B 15 ?? ?? ?? ?? 81 E2 2A 70 7F 49 81 C2 9D 83 12 3B E8 0C 50 00 00 E9 A0 16 00 00 59 5B C3 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 41 42 00 00 E9 93 33 00 00 31 DB 89 D8 59 5B C3 A1 ?? ?? ?? ?? 8A 00 2C 99 E9 82 30 00 00 0F 8A ?? ?? ?? ?? B8 01 00 00 00 31 D2 0F A2 25 FF 0F 00 00 E9 72 21 00 00 0F 86 57 0B 00 00 E9 ?? ?? ?? ?? C1 C0 03 E8 F0 36 00 00 E9 41 0A 00 00 81 F7 B3 6E 85 EA 81 C7 ?? ?? ?? ?? 87 3C 24 E9 74 52 00 00 0F 8E ?? ?? ?? ?? E8 5E 37 00 00 68 B1 74 96 13 5A E9 A1 04 00 00 81 D1 49 C0 12 27 E9 50 4E 00 00 C1 C8 1B 1B C3 81 E1 96 36 E5  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_v0_71
{
strings:
		$a0 = { 60 E8 ED 10 00 00 C3 83  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_v0_70
{
strings:
		$a0 = { 60 E8 BD 10 00 00 C3 83 E2 00 F9 75 FA 70  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_20__Eng_____dulek_xt_____Borland_Delphi___Microsoft_Visual_C___
{
strings:
		$a0 = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__XCR_0_11______Anorganix
{
strings:
		$a0 = { 60 8B F0 33 DB 83 C3 01 83 C0 01 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule nbuild_v1_0_rule__soft_
{
strings:
		$a0 = { B9 ?? ?? BB ?? ?? C0 ?? ?? 80 ?? ?? 43 E2  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___V8_0_rule__Debug_
{
strings:
		$a0 = { E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9  }

condition:
		$a0 at entrypoint
}
	
	
rule EPW_v1_2
{
strings:
		$a0 = { 06 57 1E 56 55 52 51 53 50 2E ?? ?? ?? ?? 8C C0 05 ?? ?? 2E ?? ?? ?? 8E D8 A1 ?? ?? 2E  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_1_3_3_1____Obsidium_Software
{
strings:
		$a0 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 02 ?? ?? E8 5F 27 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Hasp_dongle__Alladin_
{
strings:
		$a0 = { 50 53 51 52 57 56 8B 75 1C 8B 3E ?? ?? ?? ?? ?? 8B 5D 08 8A FB ?? ?? 03 5D 10 8B 45 0C 8B 4D 14 8B 55 18 80 FF 32  }

condition:
		$a0 at entrypoint
}
	
	
rule CExe_v1_0a
{
strings:
		$a0 = { 55 8B EC 81 EC 0C 02 ?? ?? 56 BE 04 01 ?? ?? 8D 85 F8 FE FF FF 56 50 6A ?? FF 15 54 10 40 ?? 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74 16  }

condition:
		$a0 at entrypoint
}
	
	
rule NoobyProtect_V1_X_X_X____Nooby_____Sign_By_fly___20090201
{
strings:
		$a0 = { E9 ?? 00 00 00 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 53 45 20 31 2E ?? 2E ?? 2E  }

condition:
		$a0 at entrypoint
}
	
	
rule RJcrush_v1_00
{
strings:
		$a0 = { 06 FC 8C C8 BA ?? ?? 03 D0 52 BA ?? ?? 52 BA ?? ?? 03 C2 8B D8 05 ?? ?? 8E DB 8E C0 33 F6 33 FF B9  }

condition:
		$a0 at entrypoint
}
	
	
rule KenPack_V0_X____CHKen_Com_____Sign_By_fly___20080108
{
strings:
		$a0 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E9 ?? FF FF FF 50 50 FF 35 ?? ?? ?? ?? E9 ?? FF FF FF FF 25 ?? ?? ?? ?? FF 25  }

condition:
		$a0 at entrypoint
}
	
	
rule ASDPack_2_0____asd
{
strings:
		$a0 = { 8B 44 24 04 56 57 53 E8 CD 01 00 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule ZealPack_1_0____Zeal
{
strings:
		$a0 = { C7 45 F4 00 00 40 00 C7 45 F0 ?? ?? ?? ?? 8B 45 F4 05 ?? ?? ?? ?? 89 45 F4 C7 45 FC 00 00 00 00 EB 09 8B 4D FC 83 C1 01 89 4D FC 8B 55 FC 3B 55 F0 7D 22 8B 45 F4 03 45 FC 8A 08 88 4D F8 0F BE 55 F8 83 F2 0F 88 55 F8 8B 45 F4 03 45 FC 8A 4D F8 88 08 EB CD FF 65 F4  }

condition:
		$a0 at entrypoint
}
	
	
rule PEMangle
{
strings:
		$a0 = { 60 9C BE ?? ?? ?? ?? 8B FE B9 ?? ?? ?? ?? BB 44 52 4F 4C AD 33 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule JDProtect_V20081208_demo_DLL_____________________Sign_By_fly___20090119
{
strings:
		$a0 = { 8B 44 24 08 83 F8 01 75 1F E8 92 FE FF FF E8 3D 01 00 00 8B 44 24 0C 8B 4C 24 04 50 6A 01 51 E8 5C 57 00 00 83 C4 0C C3 85 C0 75 1E 8B 54 24 0C 52 50 8B 44 24 0C 50 E8 44 57 00 00 83 C4 0C E8 7C 46 00 00 B8 01 00 00 00 C3 8B 4C 24 0C 8B 54 24 04 51 50 52 E8 26 57 00 00 83 C4 0C C3 90 90 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule PC_Guard_v3_03d__v3_05d
{
strings:
		$a0 = { 55 50 E8 ?? ?? ?? ?? 5D EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_0_96____tE_
{
strings:
		$a0 = { E9 59 E4 FF FF 00 00 00 00 00 00 00 ?? ?? ?? ?? EE ?? ?? 00 00 00 00 00 00 00 00 00 0E ?? ?? 00 FE ?? ?? 00 F6 ?? ?? 00 00 00 00 00 00 00 00 00 1B ?? ?? 00 06 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 26 ?? ?? 00 00 00 00 00 39 ?? ?? 00 00 00 00 00 26 ?? ?? 00 00 00 00 00 39 ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C  }

condition:
		$a0 at entrypoint
}
	
	
rule MinGW_GCC_DLL_v2xx
{
strings:
		$a0 = { 55 89 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? 68  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Yoda_s_Protector_1_02______Anorganix
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 90 90 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_21_Dll__LZMA_4_30_____ap0x_____Sign_By_fly___20080504
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 AF 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 E0 0C 00 00 EB 0C 8B 85 DC 0C 00 00 89 85 E0 0C 00 00 E8 87 01 00 00 8D B5 08 0D 00 00 8D 9D C6 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 71 0C 00 00 89 85 D8 0C 00 00 E8 98 01 00 00 EB 20 60 8B 85 E0 0C 00 00 FF B5 D8 0C 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD EC 0C 00 00 00 74 0E 83 BD F0 0C 00 00 00 74 05 E8 31 02 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 71 0C 00 00 89 85 04 0D 00 00 5B 60 FF B5 D8 0C 00 00 56 FF B5 04 0D 00 00 FF D3 61 8B B5 04 0D 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD E0 0C 00 00 83 C0 04 89 85 00 0D 00 00 EB 72 56 FF 95 69 0C 00 00 0B C0 75 05 E8 25 03 00 00 85 C0 0F 84 AC 00 00 00 89 85 FC 0C 00 00 8B C6 EB 2E 8B 85 00 0D 00 00 8B 00 50 FF B5 FC 0C 00 00 E8 6D 02 00 00 85 C0 0F 84 86 00 00 00 89 07 83 85 00 0D 00 00 04 83 C7 04 8B 85 00 0D 00 00 83 38 00 75 CD EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD E0 0C 00 00 83 C0 04 89 85 00 0D 00 00 80 3E 01 75 89 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 04 0D 00 00 FF 95 75 0C 00 00 68 ?? ?? ?? ?? 6A 00 FF B5 04 0D 00 00 FF 95 75 0C 00 00 68 ?? ?? ?? ?? 6A 00 FF B5 D8 0C 00 00 FF 95 75 0C 00 00 E8 A0 00 00 00 E8 9B 01 00 00 61 E9 ?? ?? ?? ?? ?? 61 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Exe_Guarder_v1_8____Exeicon_com
{
strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D B2 04 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Armor_V0_7X____hying
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 55 56 81 C5 ?? ?? ?? ?? 55 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_2_90_rule__LZMA___Delphi_stub_____Markus_Oberhumer__Laszlo_Molnar___John_Reiser
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_v2_460____Jitit
{
strings:
		$a0 = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 F4 18 40 00 50 E8 87 FC FF FF 59 59 A1 94 1A 40 00 8B 40 10 03 05 90 1A 40 00 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 76 0C 00 00 D4 0C 00 00 1E  }

condition:
		$a0 at entrypoint
}
	
	
rule Exe_Stealth_2_75a____WebtoolMaster
{
strings:
		$a0 = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72  }

condition:
		$a0 at entrypoint
}
	
	
rule XPack_1_52___1_64
{
strings:
		$a0 = { 8B EC FA 33 C0 8E D0 BC ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? EB  }

condition:
		$a0 at entrypoint
}
	
	
rule PEStubOEP_v1_x
{
strings:
		$a0 = { 40 48 BE 00 ?? ?? 00 40 48 60 33 C0 B8 ?? ?? ?? 00 FF E0 C3 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule PowerBASIC_Win_7_0x
{
strings:
		$a0 = { 55 8B EC 53 56 57 BB 00 ?? 40 00 66 2E F7 05 ?? ?? 40 00 04 00 0F 85 DB 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_2_0_0____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 02 ?? ?? E8 3F 1E 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____Borland_C___
{
strings:
		$a0 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v3_10
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E0 97 44 00 68 20 C0 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 4C 41 44 00 33 D2 8A D4 89 15 90 A1 44 00 8B C8 81 E1 FF 00 00 00 89 0D 8C A1 44 00 C1 E1 08 03 CA 89 0D 88 A1 44 00 C1 E8 10 A3 84 A1 44 00 33 F6 56 E8 72 16 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 3D 13 00 00 FF 15 30 40 44 00 A3 84 B7 44 00 E8 FB 11 00 00 A3 E0 A1 44 00 E8 A4 0F 00 00 E8 E6 0E 00 00 E8 4E F6 FF FF 89 75 D0 8D 45 A4 50 FF 15 38 40 44 00 E8 77 0E 00 00 89 45 9C F6 45 D0 01 74 06 0F B7 45 D4 EB 03 6A 0A 58 50 FF 75 9C 56 56 FF 15 7C 41 44 00 50 E8 49 D4 FE FF 89 45 A0 50 E8 3C F6 FF FF 8B 45 EC 8B 08 8B 09 89 4D 98 50 51 E8 B5 0C 00 00 59 59 C3 8B 65 E8 FF 75 98 E8 2E F6 FF FF 83 3D E8 A1 44 00 01 75 05  }

condition:
		$a0 at entrypoint
}
	
	
rule Frusion____biff
{
strings:
		$a0 = { 83 EC 0C 53 55 56 57 68 04 01 00 00 C7 44 24 14  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__LCC_Win32_1_x______Anorganix
{
strings:
		$a0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Escargot_0_1__final_______Meat
{
strings:
		$a0 = { EB 04 40 30 2E 31 60 68 61 ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 92 ?? ?? ?? 8B 00 FF D0 50 B8 CD ?? ?? ?? 81 38 DE C0 37 13 75 2D 68 C9 ?? ?? ?? 6A 40 68 00 ?? 00 00 68 00 00 ?? ?? B8 96 ?? ?? ?? 8B 00 FF D0 8B 44 24 F0 8B 4C 24 F4 EB 05 49 C6 04 01 40 0B C9 75 F7 BE 00 10 ?? ?? B9 00 ?? ?? 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE ?? ?? ?? ?? E9 AC 00 00 00 8B 46 0C BB 00 00 ?? ?? 03 C3 50 50  }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptor_V1_5____Vaska_____Sign_By_fly
{
strings:
		$a0 = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? ?? EB F3 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3  }

condition:
		$a0 at entrypoint
}
	
	
rule Petite_1_3_____c_1998_Ian_Luck
{
strings:
		$a0 = { 9C 60 50 8D 88 00 ?? ?? ?? 8D 90 ?? ?? 00 00 8B DC 8B E1 68 00 00 ?? ?? 53 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 DA 14 00 00 8B 44 24 18 F6 42 03 80 74 19 FD 80 72 03 80 8B F0 8B F8 03  }

condition:
		$a0 at entrypoint
}
	
	
rule TheHyper_s_protector____TheHyper
{
strings:
		$a0 = { 55 8B EC 83 EC 14 8B FC E8 14 00 00 00 ?? ?? 01 01 ?? ?? 01 01 ?? ?? ?? 00 ?? ?? 01 01 ?? ?? 02 01 5E E8 0D 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8B 46 04 FF 10 8B D8 E8 0D 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 53 8B 06 FF 10 89 07 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_2_rule__Borland_Delphi_DLL______Anorganix
{
strings:
		$a0 = { 55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Shrink_Wrap_v1_4
{
strings:
		$a0 = { 58 60 8B E8 55 33 F6 68 48 01 ?? ?? E8 49 01 ?? ?? EB  }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACK_v3_05c4__Unextr__Passw_check__Vir__shield_
{
strings:
		$a0 = { 03 05 C0 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Embedded_V2_547_V2_600____Jitit_____Sign_By_fly
{
strings:
		$a0 = { E8 00 00 00 00 58 BB BC 18 00 00 2B C3 50 68 ?? ?? ?? ?? 68 60 1B 00 00 68 60 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__VirusConstructor_IVP__based
{
strings:
		$a0 = { E9 ?? ?? E8 ?? ?? 5D ?? ?? ?? ?? ?? 81 ED ?? ?? ?? ?? ?? ?? E8 ?? ?? 81 FC ?? ?? ?? ?? 8D ?? ?? ?? BF ?? ?? 57 A4 A5  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Trojan_Telefoon
{
strings:
		$a0 = { 60 1E E8 3B 01 BF CC 01 2E 03 3E CA 01 2E C7 05  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_v1_18_Basic_rule__LZMA_____Ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A  }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtect_v1_1_MTEc
{
strings:
		$a0 = { 90 60 E8 1B ?? ?? ?? E9 FC  }

condition:
		$a0 at entrypoint
}
	
	
rule NSPack_3_x____Liu_Xing_Ping
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF ?? 38 01 0F 84 ?? 02 00 00 ?? 00 01  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_Basic___MASM32_
{
strings:
		$a0 = { EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47  }

condition:
		$a0 at entrypoint
}
	
	
rule Ady_s_Glue_v0_10
{
strings:
		$a0 = { 2E 8C 06 ?? ?? 0E 07 33 C0 8E D8 BE ?? ?? BF ?? ?? FC B9 ?? ?? 56 F3 A5 1E 07 5F  }

condition:
		$a0 at entrypoint
}
	
	
rule PC_Guard_v5_00d
{
strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 30 D2 40 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 89 85 E1 EA 41 00 9C EB 01 D5 9D EB 01 0B 58 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 89 85 F9 EA 41 00 9C EB 01 D5 9D EB 01 0B 89 9D E5 EA 41 00 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 89 8D E9 EA 41 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 89 95 ED EA 41 00 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 89 B5 F1 EA 41 00 9C EB 01 D5 9D EB 01 0B 89  }

condition:
		$a0 at entrypoint
}
	
	
rule PoPa_0_01__Packer_on_Pascal_____bagie
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 A4 3E 00 10 E8 30 F6 FF FF 33 C0 55 68 BE 40 00 10 ?? ?? ?? ?? 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 62 E7 FF FF 8B 45 EC E8 32 F2 FF FF 50 E8 B4 F6 FF FF A3 64 66 00 10 33 D2 55 68 93 40 00 10 64 FF 32 64 89 22 83 3D 64 66 00 10 FF 0F 84 3A 01 00 00 6A 00 6A 00 6A 00 A1 64 66 00 10 50 E8 9B F6 FF FF 83 E8 10 50 A1 64 66 00 10 50 E8 BC F6 FF FF 6A 00 68 80 66 00 10 6A 10 68 68 66 00 10 A1 64 66 00 10 50 E8 8B F6 FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule EXEPACK__LINK__v3_60__v3_64__v3_65_or_5_01_21
{
strings:
		$a0 = { 8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 ?? ?? ?? 8E C0 8B ?? ?? ?? 8B ?? 4F 8B F7 FD F3 A4 50 B8 ?? ?? 50 CB  }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor_2_2_4____Strongbit_SoftComplete_Development__h2_
{
strings:
		$a0 = { E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 ?? 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_v0_51
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 D8 01 ?? ?? 83 CD FF 31 DB ?? ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 0B 8A 06 46 88 07 47 EB EB 90  }

condition:
		$a0 at entrypoint
}
	
	
rule Unpacked_BS_SFX_Archive_v1_9
{
strings:
		$a0 = { 1E 33 C0 50 B8 ?? ?? 8E D8 FA 8E D0 BC ?? ?? FB B8 ?? ?? CD 21 3C 03 73  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Windows_Update_CAB_SFX_module
{
strings:
		$a0 = { E9 C5 FA FF FF 55 8B EC 56 8B 75 08 68 04 08 00 00 FF D6 59 33 C9 3B C1 75 0F 51 6A 05 FF 75 28 E8 2E 11 00 00 33 C0 EB 69 8B 55 0C 83 88 88 00 00 00 FF 83 88 84 00 00 00 FF 89 50 04 8B 55 10 89 50 0C 8B 55 14 89 50 10 8B 55 18 89 50 14 8B 55 1C 89 50 18 8B 55 20 89 50 1C 8B 55 24 89 50 20 8B 55 28 89 48 48 89 48 44 89 48 4C B9 FF FF 00 00 89 70 08 89 10 66 C7 80 B2 00 00 00 0F 00 89 88 A0 00 00 00 89 88 A8 00 00 00 89 88 A4 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PRO_PACK_v2_08__emphasis_on_packed_size__locked
{
strings:
		$a0 = { 83 EC ?? 8B EC BE ?? ?? FC E8 ?? ?? 05 ?? ?? 8B C8 E8 ?? ?? 8B  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_60
{
strings:
		$a0 = { 55 8B EC 6A FF 68 D0 ?? ?? ?? 68 34 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 68 ?? ?? ?? 33 D2 8A D4 89 15 84  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__LTC_1_3______Anorganix
{
strings:
		$a0 = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule MPRESS_V0_85_V0_92____MATCODE_Software_____Sign_By_fly___20080414
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 05 48 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 3B FE 73 28 AC 0A C0 74 23 8A C8 24 3F C1 E0 10 66 AD 80 E1 40 74 0F 8B D6 8B CF 03 F0 E8 5F 00 00 00 03 F8 EB D8 8B C8 F3 A4 EB D2 5E 5A 83 EA 05 2B C9 3B CA 73 25 8B D9 AC 41 24 FE 3C E8 75 F2 83 C1 04 AD 0B C0 78 06 3B C2 73 E6 EB 06 03 C3 78 E0 03 C2 2B C3 89 46 FC EB D7 E8 00 00 00 00 5F 81 C7 6A FF FF FF B0 E9 AA B8 44 01 00 00 AB E8 00 00 00 00 58 05 A3 00 00 00 E9 93 00 00 00 53 56 57 8B F9 8B F2 8B DA 03 D8 51 55 33 C0 8B EB 8B DE 2B D2 2B C9 EB 4F 3B DD 73 6C 2B C9 66 8B 03 8D 5B 02 8A CC 80 E4 0F 0B C0 75 02 B4 10 C0 E9 04 80 C1 03 80 F9 12 72 19 8A 0B 66 83 C1 12 43 66 81 F9 11 01 72 0B 66 8B 0B 81 C1 11 01 00 00 43 43 8B F7 2B F0 F3 A4 12 D2 74 0A 72 B9 8A 03 43 88 07 47 EB F2 3B DD 73 1D 0A 13 F9 74 03 43 EB E6 8B 43 01 89 07 8B 43 05 89 47 04 8D 5B 09 8D 7F 08 33 C0 EB DF 5D 8B C7 59 2B C1 5F 5E 5B C3 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule RAZOR_1911_encruptor
{
strings:
		$a0 = { E8 ?? ?? BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC  }

condition:
		$a0 at entrypoint
}
	
	
rule Joiner__sign_from_pinch_25_03_2007_20_10_
{
strings:
		$a0 = { 81 EC 04 01 00 00 8B F4 68 04 01 00 00 56 6A 00 E8 7C 01 00 00 33 C0 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 56 E8 50 01 00 00 8B D8 6A 00 6A 00 6A 00 6A 02 6A 00 53 E8 44 01  }

condition:
		$a0 at entrypoint
}
	
	
rule Exe_Shield_v2_7b
{
strings:
		$a0 = { EB 06 68 40 85 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 87 DD 8B 85 E6 90 40 00 01 85 33 90 40 00 66 C7 85 30 90 40 00 90 90 01 85 DA 90 40 00 01 85 DE 90 40 00 01 85 E2 90 40 00 BB 7B 11 00 00 03 9D EA 90 40 00 03 9D E6 90 40 00 53 8B C3 8B FB 2D AC 90 40 00 89 85 AD 90 40 00 8D B5 AC 90 40 00 B9 40 04 00 00 F3 A5 8B FB C3 BD 00 00 00 00 8B F7 83 C6 54 81 C7 FF 10 00 00 56 57 57 56 FF 95 DA 90 40 00 8B C8 5E 5F 8B C1 C1 F9 02 F3 A5 03 C8 83 E1 03 F3 A4 EB 26 D0 12 5B 00 AC 12 5B 00 48 12 5B 00 00 00 40 00 00 D0 5A 00 00 10 5B 00 87 DB 87 DB 87 DB 87 DB 87 DB 87 DB 87 DB 8B 0E B5 E6 90 40 07 56 03 76 EE 0F 18 83 C6 14 12 35 97 80 8D BD 63 39 0D B9 06 86 02 07 F3 A5 6A 04 68 06 10 12 1B FF B5 51 29 EE 10 22 95  }

condition:
		$a0 at entrypoint
}
	
	
rule DIET_v1_00d
{
strings:
		$a0 = { FC 06 1E 0E 8C C8 01 ?? ?? ?? BA ?? ?? 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_5_00____Silicon_Realms_Toolworks
{
strings:
		$a0 = { E8 E3 40 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 44 15 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 36 13 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 C7 12 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 48 11 00 00 59 89 7D FC FF 75 08 E8 01 49 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 66 D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 AF F9 FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 EE 0F 00 00 59 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_SCRAMBLER_3_06_____OnT_oL
{
strings:
		$a0 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 BE ?? ?? ?? ?? 83 EC 04 89 34 24 B9 80 00 00 00 81 36 ?? ?? ?? ?? 50 B8 04 00 00 00 50 03 34 24 58 58 83 E9 03 E2 E9 EB D6  }

condition:
		$a0 at entrypoint
}
	
	
rule MEW_11_SE_v1_2_by_Northfox
{
strings:
		$a0 = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule NsPacK_V3_6____LiuXingPing_____Sign_By_fly
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 83 38 01 0F 84 47 02 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PUNiSHER_v1_5__DEMO_____FEUERRADER_AHTeam
{
strings:
		$a0 = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 81 2C 24 CA C2 41 00 EB 04 64 6B 88 18 5D E8 00 00 00 00 EB 04 64 6B 88 18 81 2C 24 86 00 00 00 EB 04 64 6B 88 18 8B 85 9C C2 41 00 EB 04 64 6B 88 18 29 04 24 EB 04 64 6B 88 18 EB 04 64 6B 88 18 8B 04 24 EB 04 64 6B 88 18 89 85 9C C2 41 00 EB 04 64 6B 88 18 58 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 C2 50 00 EB D3 5B F3 68 89 5C 24 48 5C 24 58 FF 8D 5C 24 58 5B 83 C3 4C 75 F4 5A 8D 71 78 75 09 81 F3 EB FF 52 BA 01 00 83 EB FC 4A FF 71 0F 75 19 8B 5C 24 00 00 81 33 50 53 8B 1B 0F FF C6 75 1B 81 F3 EB 87 1C 24 8B 8B 04 24 83 EC FC EB 01 E8 83 EC FC E9 E7 00 00 00 58 EB FF F0 EB FF C0 83 E8 FD EB FF 30 E8 C9 00 00 00 89 E0 EB FF D0 EB FF 71 0F 83 C0 01 EB FF 70 F0 71 EE EB FA EB 83 C0 14 EB FF 70 ED  }

condition:
		$a0 at entrypoint
}
	
	
rule Ningishzida_1_0____CyberDoom
{
strings:
		$a0 = { 9C 60 96 E8 00 00 00 00 5D 81 ED 03 25 40 00 B9 04 1B 00 00 8D BD 4B 25 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC  }

condition:
		$a0 at entrypoint
}
	
	
rule PESPin_v1_3____Cyberbob
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF  }

condition:
		$a0 at entrypoint
}
	
	
rule vprotector_1_2____vcasm
{
strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00 00 00 00 EB E6 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 E8 05 00 00 00 0F 01 EB 05 E8 EB FB 00 00 83 C4 04 E8 08 00 00 00 0F 01 83 C0  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_Patch____Dwing
{
strings:
		$a0 = { 81 3A 00 00 00 02 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Exe_Shield_vx_x
{
strings:
		$a0 = { 65 78 65 73 68 6C 2E 64 6C 6C C0 5D 00  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_Full_Edition_1_17____Ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF  }

condition:
		$a0 at entrypoint
}
	
	
rule ExeBundle_v3_0__small_loader_
{
strings:
		$a0 = { 00 00 00 00 60 BE 00 F0 40 00 8D BE 00 20 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_VOB_ProtectCD_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 5F 81 EF 00 00 00 00 BE 00 00 40 00 8B 87 00 00 00 00 03 C6 57 56 8C A7 00 00 00 00 FF 10 89 87 00 00 00 00 5E 5F  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_v0_71b7
{
strings:
		$a0 = { 60 E8 48 11 00 00 C3 83  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_v0_71b2
{
strings:
		$a0 = { 60 E8 44 11 00 00 C3 83  }

condition:
		$a0 at entrypoint
}
	
	
rule TASM___MASM
{
strings:
		$a0 = { 6A 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule VMware_ThinApp_VV3_396_0_0____VMware_____Sign_By_fly___20090124
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB C1 20 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 2E 00 00 68 28 01 00 00 E8 2C FF FF FF E9 ?? FF FF FF CC CC CC CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PrivateEXE_v2_0a
{
strings:
		$a0 = { 06 60 C8 ?? ?? ?? 0E 68 ?? ?? 9A ?? ?? ?? ?? 3D ?? ?? 0F ?? ?? ?? 50 50 0E 68 ?? ?? 9A ?? ?? ?? ?? 0E  }
	$a1 = { 53 E8 ?? ?? ?? ?? 5B 8B C3 2D ?? ?? ?? ?? 50 81 ?? ?? ?? ?? ?? 8B  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PluginToExe_v1_02____BoB___BobSoft
{
strings:
		$a0 = { E8 00 00 00 00 29 C0 5D 81 ED 32 42 40 00 50 8F 85 DD 40 40 00 50 FF 95 11 42 40 00 89 85 D9 40 40 00 FF 95 0D 42 40 00 50 FF 95 21 42 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 25 42 40 00 89 85 E1 40 40 00 EB 6C 6A 01 8F 85 DD 40 40 00 6A 58 6A 40 FF 95 15 42 40 00 89 85 D5 40 40 00 89 C7 68 00 08 00 00 6A 40 FF 95 15 42 40 00 89 47 1C C7 07 58 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Pohernah_1_0_2___by_Kas
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED DE 26 40 00 8B BD 05 28 40 00 8B 8D 0D 28 40 00 B8 25 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 09 28 40 00 31 C0 51 31 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 09 28 40 00 8B 85 11 28 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 89 CE E8 27 00 00 00 89 C1 5F B8 25 28 40 00 01 E8 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 01 28 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 21 FE 89 F0 5F 5E C3 60 83 F0 05 40 90 48 83 F0 05 89 C6 89 D7 60 E8 0B 00 00 00 61 83 C7 08 83 E9 07 E2 F1 61 C3 57 8B 1F 8B 4F 04 68 B9 79 37 9E 5A 42 89 D0 48 C1 E0 05 BF 20 00 00 00 4A 89 DD C1 E5 04 29 E9 8B 6E 08 31 DD 29 E9 89 DD C1 ED 05 31 C5 29 E9 2B 4E 0C 89 CD C1 E5 04 29 EB 8B 2E 31 CD 29 EB 89 CD C1 ED 05 31 C5 29 EB 2B 5E 04 29 D0 4F 75 C8 5F 89 1F 89 4F 04 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Free_Pascal_v1_0_10__win32_GUI_
{
strings:
		$a0 = { C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5  }

condition:
		$a0 at entrypoint
}
	
	
rule Krypton_v0_3
{
strings:
		$a0 = { 8B 0C 24 E9 C0 8D 01 ?? C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA  }

condition:
		$a0 at entrypoint
}
	
	
rule Krypton_v0_2
{
strings:
		$a0 = { 8B 0C 24 E9 0A 7C 01 ?? AD 42 40 BD BE 9D 7A 04  }

condition:
		$a0 at entrypoint
}
	
	
rule Krypton_v0_5
{
strings:
		$a0 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 71 44 ?? ?? 2B 85 64 60 ?? ?? EB 43 DF  }

condition:
		$a0 at entrypoint
}
	
	
rule Krypton_v0_4
{
strings:
		$a0 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 61 34 ?? ?? 2B 85 60 37 ?? ?? 83 E8 06  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_v0_30_beta____Dwing
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 30  }

condition:
		$a0 at entrypoint
}
	
	
rule Ding_Boy_s_PE_lock_Phantasm_v1_0___v1_1
{
strings:
		$a0 = { 55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB FC  }

condition:
		$a0 at entrypoint
}
	
	
rule Packman_0_0_0_1____bubba
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 8D A8 ?? FE FF FF 8D 98 ?? ?? ?? FF 8D ?? ?? 01 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDote_1_2_Beta__Demo_____SIS_Team
{
strings:
		$a0 = { 68 69 D6 00 00 E8 C6 FD FF FF 68 69 D6 00 00 E8 BC FD FF FF 83 C4 08 E8 A4 FF FF FF 84 C0 74 2F 68 04 01 00 00 68 B0 21 60 00 6A 00 FF 15 08 10 60 00 E8 29 FF FF FF 50 68 88 10 60 00 68 78 10 60 00 68 B0 21 60 00 E8 A4 FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 90 90 90 90 90 90 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0  }

condition:
		$a0 at entrypoint
}
	
	
rule YZPack_1_2_____UsAr
{
strings:
		$a0 = { 4D 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_v0_80
{
strings:
		$a0 = { 60 E8 F9 11 00 00 C3 83  }

condition:
		$a0 at entrypoint
}
	
	
rule yoda_s_Protector_V1_03_3____Ashkbiz_Danehkar_____Sign_By_fly
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2D E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED 07 E2 40 00 8B D5 81 C2 56 E2 40 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Sentinel_SuperPro_Dongle_V5_42_0_0_____Rainbow_Technologies_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 10 FF 00 00 BB 00 00 00 00 E8 ?? ?? ?? ?? 68 B9 20 FF 00 00 E8 ?? ?? ?? ?? 68 B9 30 FF 00 00 E8 ?? ?? ?? ?? 68 E8 ?? ?? ?? ?? 68 27 F0 10 7F E8 ?? ?? ?? ?? 68 BB 02 00 00 00 E8 ?? ?? ?? ?? 68 07 D4 30 7F E8 ?? ?? ?? ?? 68 BB 01 00 00 00 E8 ?? ?? ?? ?? 68 50 1E DF 80 E8 ?? ?? ?? ?? 68 B9 10 12 00 00 BB 00 00 00 00 E8 ?? ?? ?? ?? 68 B9 20 12 00 00 E8 ?? ?? ?? ?? 68 E8 ?? ?? ?? ?? 68 07 2A A3 00 E8 ?? ?? ?? ?? 68 BB 01 00 00 00 E8 ?? ?? ?? ?? 68 88 B5 5B FF E8 ?? ?? ?? ?? 68 B9 30 12 00 00 BB 00 00 00 00 E8 ?? ?? ?? ?? 68  }

condition:
		$a0 at entrypoint
}
	
	
rule Install_Stub_32_bit
{
strings:
		$a0 = { 55 8B EC 81 EC 14 ?? 00 00 53 56 57 6A 00 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 29  }

condition:
		$a0 at entrypoint
}
	
	
rule hmimys_Packer_V1_2____hmimys_____Sign_By_fly
{
strings:
		$a0 = { E8 95 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5E AD 50 AD 50 97 AD 50 AD 50 AD 50 E8 C0 01 00 00 AD 50 AD 93 87 DE B9 ?? ?? ?? ?? E3 1D 8A 07 47 04 ?? 3C ?? 73 F7 8B 07 3C ?? 75 F3 B0 00 0F C8 05 ?? ?? ?? ?? 2B C7 AB E2 E3 AD 85 C0 74 2B 97 56 FF 13 8B E8 AC 84 C0 75 FB 66 AD 66 85 C0 74 E9 AC 83 EE 03 84 C0 74 08 56 55 FF 53 04 AB EB E4 AD 50 55 FF 53 04 AB EB E0 C3 8B 0A 3B 4A 04 75 0A C7 42 10 01 00 00 00 0C FF C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_0_22___0_23_beta____Dwing
{
strings:
		$a0 = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 59 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Password_protector_my_SMT
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 5D 8B FD 81 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 46 80 ?? ?? 74  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Caz_1204
{
strings:
		$a0 = { E8 ?? ?? 5E 83 EE 03 1E 06 B8 FF FF CD 2F 3C 10  }

condition:
		$a0 at entrypoint
}
	
	
rule ACProtect_V1_4X____risco
{
strings:
		$a0 = { 60 E8 01 00 00 00 7C 83 04 24 06 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Reg2Exe_2_22_2_23___by_Jan_Vorel
{
strings:
		$a0 = { 6A 00 E8 2F 1E 00 00 A3 C4 35 40 00 E8 2B 1E 00 00 6A 0A 50 6A 00 FF 35 C4 35 40 00 E8 07 00 00 00 50 E8 1B 1E 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 C8 35 40 00 E8 76 16 00 00 83 C4 0C 8B 44 24 04 A3 CC 35 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 EC 1D 00 00 A3 C8 35 40 00 E8 62 1D 00 00 E8 92 1A 00 00 E8 80 16 00 00 E8 13 14 00 00 68 01 00 00 00 68 08 36 40 00 68 00 00 00 00 8B 15 08 36 40 00 E8 71 3F 00 00 B8 00 00 10 00 BB 01 00 00 00 E8 82 3F 00 00 FF 35 48 31 40 00 B8 00 01 00 00 E8 0D 13 00 00 8D 0D EC 35 40 00 5A E8 F2 13 00 00 68 00 01 00 00 FF 35 EC 35 40 00 E8 84 1D 00 00 A3 F4 35 40 00 FF 35 48 31 40 00 FF 35 F4 35 40 00 FF 35 EC 35 40 00 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule Fish_PE_Shield_1_12_1_16____HellFish
{
strings:
		$a0 = { 60 E8 EA FD FF FF FF D0 C3 8D 40 00 ?? 00 00 00 2C 00 00 00 ?? ?? ?? 00 ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 ?? ?? 00 ?? ?? 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 00 00 ?? ?? ?? 00 40 ?? ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 40 ?? ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 40  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_Full_Edition_1_17_DLL_rule__aPLib_____Ap0x
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 53 03 00 00 8D 9D 02 02 00 00 33 FF E8 ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_PEtite_2_1_____emadicius
{
strings:
		$a0 = { B8 00 50 40 00 6A 00 68 BB 21 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 83 C4 04 61 66 9D 64 8F 05 00 00 00 00 83 C4 08 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule HASP_HL_Protection_V1_X____Aladdin_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC 53 56 57 60 8B C4 A3 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 15 8B 0D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 83 C4 04 E9 A5 00 00 00 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B 15  }

condition:
		$a0 at entrypoint
}
	
	
rule EXEStealth_2_75____WebtoolMaster
{
strings:
		$a0 = { 90 60 90 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____bart_xt____WinRAR_SFX
{
strings:
		$a0 = { 80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0  }
	$a1 = { EB 01 02 EB 02 CD 20 B8 80 ?? 42 00 EB 01 55 BE F4 00 00 00 13 DF 13 D8 0F B6 38 D1 F3 F7  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule DJoin_v0_7_public__RC4_encryption_____drmist
{
strings:
		$a0 = { C6 05 ?? ?? 40 00 00 C6 05 ?? ?? 40 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Embedded_V1_9X____Jitit_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 ?? ?? ?? ?? 50 E8 87 FC FF FF 59 59 A1 ?? ?? ?? ?? 8B 40 10 03 05 ?? ?? ?? ?? 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule dePACK_V1_0___deNULL_____Sign_By_fly
{
strings:
		$a0 = { EB 01 DD 60 68 00 ?? ?? ?? 68 ?? ?? 00 00 E8 ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? D2  }

condition:
		$a0 at entrypoint
}
	
	
rule SDC_1_2__Self_Decrypting_Binary_Generator____by_Claes_M_Nyberg
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 A0 91 40 00 E8 DB FE FF FF 55 89 E5 53 83 EC 14 8B 45 08 8B 00 8B 00 3D 91 00 00 C0 77 3B 3D 8D 00 00 C0 72 4B BB 01 00 00 00 C7 44 24 04 00 00 00 00 C7 04 24 08 00 00 00 E8 CE 24 00 00 83 F8 01 0F 84 C4 00 00 00 85 C0 0F 85 A9 00 00 00 31 C0 83 C4 14 5B 5D C2 04 00 3D 94 00 00 C0 74 56 3D 96 00 00 C0 74 1E 3D 93 00 00 C0 75 E1 EB B5 3D 05 00 00 C0 8D B4 26 00 00 00 00 74 43 3D 1D 00 00 C0 75 CA C7 44 24 04 00 00 00 00 C7 04 24 04 00 00 00 E8 73 24 00 00 83 F8 01 0F 84 99 00 00 00 85 C0 74 A9 C7 04 24 04 00 00 00 FF D0 B8 FF FF FF FF EB 9B 31 DB 8D 74 26 00 E9 69 FF FF FF C7 44 24 04 00 00 00 00 C7 04 24 0B 00 00 00 E8 37 24 00 00 83 F8 01 74 7F 85 C0 0F 84 6D FF FF FF C7 04 24 0B 00 00 00 8D 76 00 FF D0 B8 FF FF FF FF E9 59 FF FF FF C7 04 24 08 00 00 00 FF D0 B8 FF FF FF FF E9 46 FF FF FF C7 44 24 04 01 00 00 00 C7 04 24 08 00 00 00 E8 ED 23 00 00 B8 FF FF FF FF 85 DB 0F 84 25 FF FF FF E8 DB 15 00 00 B8 FF FF FF FF E9 16 FF FF FF C7 44 24 04 01 00 00 00 C7 04 24 04 00 00 00 E8 BD 23 00 00 B8 FF FF FF FF E9 F8 FE FF FF C7 44 24 04 01 00 00 00 C7 04 24 0B 00 00 00 E8 9F 23 00 00 B8 FF FF FF FF E9 DA FE FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule PcShare____________v4_0____________
{
strings:
		$a0 = { 55 8B EC 6A FF 68 90 34 40 00 68 B6 28 40 00 64 A1  }

condition:
		$a0 at entrypoint
}
	
	
rule Lite_v0_03a
{
strings:
		$a0 = { 60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 ?? 10 ?? ?? 68  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE_Stealth_v1_1
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED FB 1D 40 00 B9 7B 09 00 00 8B F7 AC  }

condition:
		$a0 at entrypoint
}
	
	
rule AHpack_0_1____FEUERRADER
{
strings:
		$a0 = { 60 68 54 ?? ?? ?? B8 48 ?? ?? ?? FF 10 68 B3 ?? ?? ?? 50 B8 44 ?? ?? ?? FF 10 68 00 ?? ?? ?? 6A 40 FF D0 89 05 CA ?? ?? ?? 89 C7 BE 00 10 ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_31
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9  }

condition:
		$a0 at entrypoint
}
	
	
rule Anticrack_Software_Protector_v1_09__ACProtect_
{
strings:
		$a0 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00  }
	$a1 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 04 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 78 03 79 01 ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00  }
	$a2 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 83 04 24 06 C3 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66  }
	$a3 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0___7_0___ASM_
{
strings:
		$a0 = { E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 ?? ?? 00 8B FA EB 01 A8  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_5_2____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 03 ?? ?? ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule FreeBASIC_0_16b
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 88 FF FF FF 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 68 FF FF FF 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 45 08 89 04 24 FF 15 ?? ?? ?? 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 45 08 89 04 24 FF 15 ?? ?? ?? 00 89 EC 5D C3 90 90 90 90 90 90 90 90 90 90  }

condition:
		$a0 at entrypoint
}
	
	
rule vfp_exeNc_V5_00____Wang_JianGuo_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_0_21_beta____Dwing
{
strings:
		$a0 = { BE 88 01 40 00 AD 8B F8 6A 04 95 A5 33 C0 AB 48 AB F7 D8 59 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin_v1_3beta____Cyberbob
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Video_Lan_Client______Anorganix
{
strings:
		$a0 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule theWRAP___by_TronDoc
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 48 D2 4B 00 E8 BC 87 F4 FF BB 04 0B 4D 00 33 C0 55 68 E8 D5 4B 00 64 FF 30 64 89 20 E8 9C F4 FF FF E8 F7 FB FF FF 6A 40 8D 55 F0 A1 F0 ED 4B 00 8B 00 E8 42 2E F7 FF 8B 4D F0 B2 01 A1 F4 C2 40 00 E8 F7 20 F5 FF 8B F0 B2 01 A1 B4 C3 40 00 E8 F1 5B F4 FF 89 03 33 D2 8B 03 E8 42 1E F5 FF 66 B9 02 00 BA FC FF FF FF 8B C6 8B 38 FF 57 0C BA B8 A7 4D 00 B9 04 00 00 00 8B C6 8B 38 FF 57 04 83 3D B8 A7 4D 00 00 0F 84 5E 01 00 00 8B 15 B8 A7 4D 00 83 C2 04 F7 DA 66 B9 02 00 8B C6 8B 38 FF 57 0C 8B 0D B8 A7 4D 00 8B D6 8B 03 E8 2B 1F F5 FF 8B C6 E8 B4 5B F4 FF 33 D2 8B 03 E8 DF 1D F5 FF BA F0 44 4E 00 B9 01 00 00 00 8B 03 8B 30 FF 56 04 80 3D F0 44 4E 00 0A 75 3F BA B8 A7 4D 00 B9 04 00 00 00 8B 03 8B 30 FF 56 04 8B 15 B8 A7  }

condition:
		$a0 at entrypoint
}
	
	
rule Alex_Protector_v0_4_beta_1_by_Alex
{
strings:
		$a0 = { 60 E8 01 00 00 00 C7 83 C4 04 33 C9 E8 01 00 00 00 68 83 C4 04 E8 01 00 00 00 68 83 C4 04 B9 ?? 00 00 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 01 00 00 00 C7 83 C4 04 8B 2C 24 83 C4 04 E8 01 00 00 00 A9 83 C4 04 81 ED 3C 13 40 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 00 00 00 00 49 E8 01 00 00 00 68 83 C4 04 85 C9 75 DF E8 B9 02 00 00 E8 01 00 00 00 C7 83 C4 04 8D 95 63 14 40 00 E8 01 00 00 00 C7 83 C4 04 90 90 90 E8 CA 01 00 00 01 02 03 04 05 68 90 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_v0_89_6___v1_02___v1_05___v1_22_Modified
{
strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_PESHiELD_0_25_____emadicius
{
strings:
		$a0 = { 60 E8 2B 00 00 00 0D 0A 0D 0A 0D 0A 52 65 67 69 73 74 41 72 65 64 20 74 6F 3A 20 4E 4F 4E 2D 43 4F 4D 4D 45 52 43 49 41 4C 21 21 0D 0A 0D 0A 0D 00 58 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_SHiELD_0_2
{
strings:
		$a0 = { 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____MASM32___TASM32___Microsoft_Visual_Basic_
{
strings:
		$a0 = { F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94  }

condition:
		$a0 at entrypoint
}
	
	
rule Themida_WinLicense_V1_0_0_0_V1_8_0_0____Oreans_Technologies_____Sign_By_fly
{
strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? E8 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_v0_81___v0_84_Modified
{
strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_V0_10_V0_12____Dwing_____Sign_By_fly___20080321
{
strings:
		$a0 = { BE ?? ?? ?? ?? AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9E 0C 10 00 00 B0 01 67 E3 29 8B D7 2B 56 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF D5 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 55 CC 33 C9 E9 DF 00 00 00 8B 5E 0C 83 C2 30 FF D5 73 50 83 C2 30 FF D5 72 1B 83 C2 30 FF D5 72 2B 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 46 0C B1 80 8A 00 EB CF 83 C2 60 FF D5 87 5E 10 73 0D 83 C2 30 FF D5 87 5E 14 73 03 87 5E 18 3C 07 B0 08 72 02 B0 0B 50 53 8D 96 7C 07 00 00 FF 55 D0 5B 91 EB 77 3C 07 B0 07 72 02 B0 0A 50 87 5E 10 87 5E 14 89 5E 18 8D 96 C4 0B 00 00 FF 55 D0  }

condition:
		$a0 at entrypoint
}
	
	
rule Crunch_v4_0
{
strings:
		$a0 = { EB 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 18 00 00 00 8B C5 55 60 9C 2B 85 E9 06 00 00 89 85 E1 06 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 03 00 00 89 85 D9 41 00 00 68 EC 49 7B 79 33 C0 50 E8 11 03 00 00 89 85 D1 41 00 00 E8 67 05 00 00 E9 56 05 00 00 51 52 53 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 D8 73 09 66 35 20 83 66 81 F3 B8 ED FE CE 75 EB 33 C8 33 D3 4F 75 D5 F7 D2 F7 D1 5B 8B C2 C1 C0 10 66 8B C1 5A 59 C3 68 03 02 00 00 E8 80 04 00 00 0F 82 A8 02 00 00 96 8B 44 24 04 0F C8 8B D0 25 0F 0F 0F 0F 33 D0 C1 C0 08 0B C2 8B D0 25 33 33 33 33 33 D0 C1 C0 04 0B C2 8B D0 25 55 55 55 55 33 D0 C1 C0 02 0B C2  }

condition:
		$a0 at entrypoint
}
	
	
rule Fish_Pe_Packer_V1_04_V1_0X____hellfish_____Sign_By_fly___20090120
{
strings:
		$a0 = { 60 B8 ?? ?? ?? ?? FF D0 5A 00 00 ?? ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 57 56 53 55 89 E5 8B 45 20 01 45 24 50 FC 8B 75 18 01 75 1C 56 8B 75 14 AD 92 52 8A 4E FE 83 C8 FF D3 E0 F7 D0 50 88 F1 83 C8 FF D3 E0 F7 D0 50 00 D1 89 F7 83 EC 0C 29 C0 40 50 50 50 50 50 57 AD 89 C1 AD 29 F6 56 83 CB FF F3 AB 6A 05 59 E8 9C 02 00 00 E2 F9 8D 36 8D 3F 8B 7D FC 8B 45 F0 2B 7D 20 21 F8 89 45 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule dUP2____diablo2oo2
{
strings:
		$a0 = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 3C 01 75 19 BE ?? ?? ?? ?? 68 00 02 00 00 56 68  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE_v1_00c__2_
{
strings:
		$a0 = { BA ?? ?? A1 ?? ?? 2D ?? ?? 8C CB 81 C3 ?? ?? 3B C3 77 ?? 05 ?? ?? 3B C3 77 ?? B4 09 BA ?? ?? CD 21 CD 20 90  }

condition:
		$a0 at entrypoint
}
	
	
rule CodeSafe_v2_0
{
strings:
		$a0 = { 83 EC 10 53 56 57 E8 C4 01 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_V0_22_V0_23____Dwing_____Sign_By_fly___20080321
{
strings:
		$a0 = { 6A 07 BE ?? ?? ?? ?? AD 8B F8 59 95 F3 A5 AD ?? ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 59 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF ?? ?? ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 01 E3 29 8B D7 2B 55 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 56 08 33 C9 E9 07 01 00 00 8B 5D 0C 83 C2 30 FF 16 73 53 83 C2 30 FF 16 72 1B 83 C2 30 FF 16 72 2B 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 45 0C B1 80 8A 00 EB CF 83 C2 60 FF 16 87 5D 10 73 0D 83 C2 30 FF 16 87 5D 14 73 03 87 5D 18 3C 07 B0 08 72 02 B0 0B 50 53 8D 95 7C 07 00 00 FF 56 0C 5B 91 E9 9C 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin_v1_304____Cyberbob
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_v0_399____Dwing
{
strings:
		$a0 = { 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? 00 00 02 00 00 00 00 00 00 ?? 00 00 00 00 00 10 00 00 ?? 00 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? 00 14 00 00 00 00 ?? ?? 00 ?? ?? 00 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? 00 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? 00 ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5  }
	$a1 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 10 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? 00 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 99 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Pack_Master_1_0__PEX_Clone_______Anorganix
{
strings:
		$a0 = { 60 E8 01 01 00 00 E8 83 C4 04 E8 01 90 90 90 E9 5D 81 ED D3 22 40 90 E8 04 02 90 90 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_3_6____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? ?? ?? ?? ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 01 ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04  }

condition:
		$a0 at entrypoint
}
	
	
rule ExeSmasher_vx_x
{
strings:
		$a0 = { 9C FE 03 ?? 60 BE ?? ?? 41 ?? 8D BE ?? 10 FF FF 57 83 CD FF EB 10  }

condition:
		$a0 at entrypoint
}
	
	
rule SoftProtect____SoftProtect_by_ru
{
strings:
		$a0 = { EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 60 E8 03 ?? ?? ?? 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 EB 01 83 9C EB 01 D5 EB 08 35 9D EB 01 89 EB 03 0B EB F7 E8 ?? ?? ?? ?? 58 E8 ?? ?? ?? ?? 59 83 01 01 80 39 5C  }

condition:
		$a0 at entrypoint
}
	
	
rule ROD_High_TECH____Ayman
{
strings:
		$a0 = { 60 8B 15 1D 13 40 00 F7 E0 8D 82 83 19 00 00 E8 58 0C 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Doom_666
{
strings:
		$a0 = { E8 ?? ?? ?? 5E 83 EE ?? B8 CF 7B CD 21 3D CF 7B ?? ?? 0E 1F 81 C6 ?? ?? BF ?? ?? B9 ?? ?? FC F3 A4 06 1F 06 B8 ?? ?? 50 CB B4 48 BB 2C 00 CD 21  }

condition:
		$a0 at entrypoint
}
	
	
rule Petite_2_2_____c_1998_99_Ian_Luck
{
strings:
		$a0 = { 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 68 00 00 ?? ?? 8B 3C 24 8B 30 66 81 C7 80 07 8D 74 06 08 89 38 8B 5E 10 50 56 6A 02 68 80 08 00 00 57 6A ?? 6A 06 56 6A 04 68 80 08 00 00 57 FF D3 83 EE 08 59 F3 A5 59 66  }

condition:
		$a0 at entrypoint
}
	
	
rule BobPack_v1_00_____BoB___BobSoft
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 0C 24 89 CD 83 E9 06 81 ED ?? ?? ?? ?? E8 3D 00 00 00 89 85 ?? ?? ?? ?? 89 C2 B8 5D 0A 00 00 8D 04 08 E8 E4 00 00 00 8B 70 04 01 D6 E8 76 00 00 00 E8 51 01 00 00 E8 01 01  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Virtualization_Suite_V3_104_V3_332____Thinstall_Company_____Sign_By_fly___20080318
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB CC 1A 00 00 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 C8 00 00 00 E8 2C FF FF FF E9 ?? FF FF FF CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 C3 B9 08 00 00 00 E8 01 00 00 00 C3 33 C0 E8 E1 FF FF FF 13 C0 E2 F7 C3 33 C9 41 E8 D4 FF FF FF 13 C9 E8 CD FF FF FF 72 F2 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule SafeGuard_V1_0X____simonzh2000_____Sign_By_fly
{
strings:
		$a0 = { E8 00 00 00 00 EB 29 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 59 9C 81 C1 E2 FF FF FF EB 01 ?? 9D FF E1  }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptor_v1_6____Vaska
{
strings:
		$a0 = { 33 D0 68 ?? ?? ?? ?? FF D2 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3  }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor_V2_2X_V2_4X____StrongBit_Technology_____Sign_By_fly
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 05 ?? ?? ?? ?? FF E0 E8 ?? ?? ?? ?? 05 ?? ?? ?? ?? FF E0 E8 04 00 00 00 FF FF FF FF 5E C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Patch_Creation_Wizard_v1_2_Seek_and_Destroy_Patch
{
strings:
		$a0 = { E8 C5 05 00 00 6A 00 E8 5E 05 00 00 A3 CE 39 40 00 6A 00 68 29 10 40 00 6A 00 6A 01 50 E8 72 05 00 00 6A 00 E8 2F 05 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C1 00 00 00 6A 01 FF 35 CE 39 40 00 E8 61 05 00 00 50 6A 01 68 80 00 00 00 FF 75 08 E8 63 05 00 00 68 5F 30 40 00 6A 65 FF 75 08 E8 5A 05 00 00 68 B0 30 40 00 6A 67 FF 75 08 E8 4B 05 00 00 68 01 31 40 00 6A 66 FF 75 08 E8 3C 05 00 00 6A 00 FF 75 08 E8 0E 05 00 00 A3 CA 39 40 00 C7 05 D2 39 40 00 2C 00 00 00 C7 05 D6 39 40 00 10 00 00 00 C7 05 DA 39 40 00 00 08 00 00 68 D2 39 40 00 6A 01 6A FF FF 35 CA 39 40 00 E8 DD 04 00 00 C7 05 DA 39 40 00 00 00 00 00 C7 05 F6 39 40 00 00 30 40 00 C7 05 FA 39 40 00 01 00 00 00 68 D2 39 40 00 6A 01 6A FF FF 35 CA 39 40 00 E8 AB 04 00 00 EB 5F EB 54  }

condition:
		$a0 at entrypoint
}
	
	
rule PEShit
{
strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 83 F9 00 7E 06 80 30 ?? 40 E2 F5 E9 ?? ?? ?? FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_2_2____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 2A 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 04  }

condition:
		$a0 at entrypoint
}
	
	
rule nPack_V1_1_150_2006_Beta____NEOx_rule__uinC_
{
strings:
		$a0 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? ?? E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 3C ?? ?? ?? C7 05 40 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_v0_21_Beta____Dwing
{
strings:
		$a0 = { BE 88 01 ?? ?? AD 8B F8 ?? ?? ?? ?? 33  }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor_1_2_0_Beta_PE_Packer
{
strings:
		$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 EB ?? 45 78 50 72 2D 76 2E 31 2E 32 2E 2E  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_1_0_beta____ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 F9 01 00 00 89 85 48 02 00 00 5B FF B5 48 02 00 00 56 FF D3 83 C4 08 8B B5 48 02 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 83 C0 04 89 85 44 02 00 00 EB 7A 56 FF 95 F1 01 00 00 89 85 40 02 00 00 8B C6 EB 4F 8B 85 44 02 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 44 02 00 00 C7 00 20 20 20 00 EB 06 FF B5 44 02 00 00 FF B5 40 02 00 00 FF 95 F5 01 00 00 89 07 83 C7 04 8B 85 44 02 00 00 EB 01 40 80 38 00 75 FA 40 89 85 44 02 00 00 80 38 00 75 AC EB 01 46 80 3E 00 75 FA 46 40 8B 38 83 C0 04 89 85 44 02 00 00 80 3E 01 75 81 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 48 02 00 00 FF 95 FD 01 00 00 61 68 ?? ?? ?? ?? C3 60 8B 74 24 24 8B 7C  }

condition:
		$a0 at entrypoint
}
	
	
rule DBPE_v2_10
{
strings:
		$a0 = { 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 C4 04 9D EB 01 75 68 5F 20 40 ?? E8 B0 EF FF FF 72 03 73 01 75 BE  }
	$a1 = { EB 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? EB 58 75 73 65 72 33 32 2E 64 6C 6C ?? 4D 65 73 73 61 67 65 42 6F 78 41 ?? 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C ?? 53 6C 65 65 70 ?? 47 65 74 54 69 63 6B 43 6F 75 6E 74  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule EXE_Stealth_v2_7
{
strings:
		$a0 = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED D3 26 40  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE_Stealth_v2_5
{
strings:
		$a0 = { 60 90 EB 22 45 78 65 53 74 65 61 6C 74 68 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D E8 00 00 00 00 5D 81 ED 40 1E 40 00 B9 99 09 00 00 8D BD 88 1E 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_15_V1_17__aPlib_0_43_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_v1_03___v1_04
{
strings:
		$a0 = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v2_xx
{
strings:
		$a0 = { A8 03 ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 8B 85 26 04 ?? ?? 8D 8D 3B 04 ?? ?? 51 50 FF 95  }
	$a1 = { A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule EXECryptor_v1_3_0_45
{
strings:
		$a0 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1  }
	$a1 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ASPack_v1_061b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43  }

condition:
		$a0 at entrypoint
}
	
	
rule Themida_1_2_0_1__compressed_____Oreans_Technologies
{
strings:
		$a0 = { B8 00 00 ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8  }

condition:
		$a0 at entrypoint
}
	
	
rule AZProtect_0001___by_AlexZ_aka_AZCRC
{
strings:
		$a0 = { EB 70 FC 60 8C 80 4D 11 00 70 25 81 00 40 0D 91 BB 60 8C 80 4D 11 00 70 21 81 1D 61 0D 81 00 40 CE 60 8C 80 4D 11 00 70 25 81 25 81 25 81 25 81 29 61 41 81 31 61 1D 61 00 40 B7 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 60 BE 00 ?? ?? 00 BF 00 00 40 00 EB 17 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 00 00 FF 25 ?? ?? ?? 00 8B C6 03 C7 8B F8 57 55 8B EC 05 7F 00 00 00 50 E8 E5 FF FF FF BA 8C ?? ?? 00 89 02 E9 1A 01 00 00 ?? 00 00 00 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 47 65 74 56 6F 6C 75 6D 65 49 6E 66 6F 72 6D 61 74 69 6F 6E 41 00 4D 65 73 73 61 67 65 42 6F 78 41 00 45 78 69 74 50 72 6F 63 65 73 73 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41  }

condition:
		$a0 at entrypoint
}
	
	
rule Packed_with__PKLITE_v1_50_with_CRC_check__1_
{
strings:
		$a0 = { 1F B4 09 BA ?? ?? CD 21 B8 ?? ?? CD 21  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Hymn_1865
{
strings:
		$a0 = { E8 ?? ?? 5E 83 EE 4C FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 ?? ?? ?? FB 3B ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? 50 06 56 1E 0E 1F B8 00 C5 CD 21  }

condition:
		$a0 at entrypoint
}
	
	
rule NsPack_3_4____North_Star
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF 80 38 01 0F 84 42 02 00 00 C6 00 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5  }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin_V0_41____cyberbob_____Sign_By_fly___20080312
{
strings:
		$a0 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 02 D2 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 ?? ?? ?? ?? ?? 53 8F ?? ?? ?? ?? ?? BB ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 ?? 68 3C 01 00 00 59 8D ?? ?? ?? ?? ?? C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 ?? ?? ?? ?? 59 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 ?? E8 1A 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Naked_Packer_V1_X____BigBoote_____Sign_By_fly
{
strings:
		$a0 = { 6A ?? E8 9A 05 00 00 8B D8 53 68 ?? ?? ?? ?? E8 6C FD FF FF B9 05 00 00 00 8B F3 BF ?? ?? ?? ?? 53 F3 A5 E8 8D 05 00 00 8B 3D ?? ?? ?? ?? A1 ?? ?? ?? ?? 66 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B CF 89 45 E8 89 0D ?? ?? ?? ?? 66 89 55 EC 8B 41 3C 33 D2 03 C1 83 C4 10 66 8B 48 06 66 8B 50 14 81 E1 FF FF 00 00 8D 5C 02 18 8D 41 FF E8 00 00 00 00 EB 01 ?? 89 45 F0 C6 45 FF 00 8D 7D E8 8B F3 8A 0E 8A 17 8A C1 3A CA 75 1E 84 C0 74 16 8A 56 01 8A 4F 01 8A C2 3A D1 75 0E 83 C6 02 83 C7 02 84 C0 75 DC 33 C0 EB 05  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_0_99c__Private_ECLIPSE_____tE_
{
strings:
		$a0 = { E9 3F DF FF FF 00 00 00 ?? ?? ?? ?? 04 ?? ?? 00 00 00 00 00 00 00 00 00 24 ?? ?? 00 14 ?? ?? 00 0C ?? ?? 00 00 00 00 00 00 00 00 00 31 ?? ?? 00 1C ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3C ?? ?? 00 00 00 00 00 4F ?? ?? 00 00 00 00 00 3C ?? ?? 00 00 00 00 00 4F ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65  }

condition:
		$a0 at entrypoint
}
	
	
rule KByS_V0_28_DLL____shoooo_____Sign_By_fly
{
strings:
		$a0 = { B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 03 C2 FF E0 ?? ?? ?? ?? 60 E8 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACK_v3_00__v3_01__Extractable_
{
strings:
		$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 6A ?? 06 06 8C D3 83 ?? ?? 53 6A ?? FC  }

condition:
		$a0 at entrypoint
}
	
	
rule NsPacK_V3_1____LiuXingPing_____Sign_By_fly
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74  }

condition:
		$a0 at entrypoint
}
	
	
rule Ding_Boy_s_PE_lock_Phantasm_v0_8
{
strings:
		$a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 0D 39 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PEnguinCrypt_v1_0
{
strings:
		$a0 = { B8 93 ?? ?? 00 55 50 67 64 FF 36 00 00 67 64 89 26 00 00 BD 4B 48 43 42 B8 04 00 00 00 CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 00 00 58 5D BB 00 00 40 00 33 C9 33 C0  }

condition:
		$a0 at entrypoint
}
	
	
rule MPRESS_V0_77b____MATCODE_Software_____Sign_By_fly___20080313
{
strings:
		$a0 = { 60 E8 0B 00 00 00 E8 77 00 00 00 61 E9 75 01 00 00 E8 00 00 00 00 58 05 75 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 AD 2B C8 03 F1 8B C8 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 3B FE 73 3A AC 0A C0 74 35 8A C8 24 3F 80 E1 C0 C1 E0 10 66 AD 80 F9 C0 74 1C F6 C1 40 75 08 8B C8 2B C0 F3 AA EB D7 8B D6 8B CF 03 F0 E8 7E 00 00 00 03 F8 EB C8 8B C8 F3 A4 75 FC EB C0 C3 E8 00 00 00 00 5F 81 C7 79 FF FF FF B0 E9 AA B8 81 01 00 00 AB 2B FF E8 00 00 00 00 58 05 ED 00 00 00 8B 78 08 8B D7 8B 78 04 0B FF 74 42 8B 30 03 F0 2B F2 8B EE 8B 48 10 2B CD 74 33 8B 50 0C 03 F2 03 FE 2B C0 AD 3B F7 73 25 8B D8 AD 3B F7 73 1E 8B D0 83 EA 08 03 D6 66 AD 0A E4 74 0B 25 FF 0F 00 00 03 C3 03 C5 29 08 3B F2 73 D8 EB E9 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__VCL
{
strings:
		$a0 = { AC B9 00 80 F2 AE B9 04 00 AC AE 75 ?? E2 FA 89  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_V0_36_V0_37__DLL_____Dwing
{
strings:
		$a0 = { 60 E8 09 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 5E 87 0E  }

condition:
		$a0 at entrypoint
}
	
	
rule Shrink_v2_0
{
strings:
		$a0 = { E9 ?? ?? 50 9C FC BE ?? ?? 8B FE 8C C8 05 ?? ?? 8E C0 06 57 B9  }

condition:
		$a0 at entrypoint
}
	
	
rule ACProtect_1_09g____Risco_software_Inc_
{
strings:
		$a0 = { 60 F9 50 E8 01 00 00 00 7C 58 58 49 50 E8 01 00 00 00 7E 58 58 79 04 66 B9 B8 72 E8 01 00 00 00 7A 83 C4 04 85 C8 EB 01 EB C1 F8 BE 72 03 73 01 74 0F 81 01 00 00 00 F9 EB 01 75 F9 E8 01 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule VMware_ThinApp_V4_0_0_2200____VMware_____Sign_By_fly___20090124
{
strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 94 1A 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 28 00 00 68 C8 00 00 00 E8 2C FF FF FF E9 ?? FF FF FF CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_0_37____Obsidium_Software_____Sign_By_haggar
{
strings:
		$a0 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor_2_3_9__minimum_protection_
{
strings:
		$a0 = { 68 ?? ?? ?? ?? E9 ?? ?? ?? FF 50 C1 C8 18 89 05 ?? ?? ?? ?? C3 C1 C0 18 51 E9 ?? ?? ?? FF 84 C0 0F 84 6A F9 FF FF E9 ?? ?? ?? FF C3 E9 ?? ?? ?? FF E8 CF E9 FF FF B8 01 00 00 00 E9 ?? ?? ?? FF 2B D0 68 A0 36 80 D4 59 81 C9 64 98 FF 99 E9 ?? ?? ?? FF 84 C0 0F 84 8E EC FF FF E9 ?? ?? ?? FF C3 87 3C 24 5F 8B 00 03 45 FC 83 C0 18 E9 ?? ?? ?? FF 87 0C 24 59 B8 01 00 00 00 D3 E0 23 D0 E9 02 18 00 00 0F 8D DB 00 00 00 C1 E8 14 E9 CA 00 00 00 9D 87 0C 24 59 87 1C 24 68 AE 73 B9 96 E9 C5 10 00 00 0F 8A ?? ?? ?? ?? E9 ?? ?? ?? FF 81 FD F5 FF 8F 07 E9 4F 10 00 00 C3 E9 5E 12 00 00 87 3C 24 E9 ?? ?? ?? FF E8 ?? ?? ?? FF 83 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 8D 55 EC B8 ?? ?? ?? ?? E9 ?? ?? ?? FF E8 A7 1A 00 00 E8 2A CB FF FF E9 ?? ?? ?? FF C3 E9 ?? ?? ?? FF 59 89 45 E0  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0___ASM_
{
strings:
		$a0 = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68  }

condition:
		$a0 at entrypoint
}
	
	
rule JExeCompressor_1_0___by_Arash_Veyskarami
{
strings:
		$a0 = { 8D 2D D3 4A E5 14 0F BB F7 0F BA E5 73 0F AF D5 8D 0D 0C 9F E6 11 C0 F8 EF F6 DE 80 DC 5B F6 DA 0F A5 C1 0F C1 F1 1C F3 4A 81 E1 8C 1F 66 91 0F BE C6 11 EE 0F C0 E7 33 D9 64 F2 C0 DC 73 0F C0 D5 55 8B EC BA C0 1F 41 00 8B C2 B9 97 00 00 00 80 32 79 50 B8 02 00 00 00 50 03 14 24 58 58 51 2B C9 B9 01 00 00 00 83 EA 01 E2 FB 59 E2 E1 FF E0  }

condition:
		$a0 at entrypoint
}
	
	
rule DzA_Patcher_v1_3_Loader
{
strings:
		$a0 = { BF 00 40 40 00 99 68 48 20 40 00 68 00 20 40 00 52 52 52 52 52 52 52 57 E8 15 01 00 00 85 C0 75 1C 99 52 52 57 52 E8 CB 00 00 00 FF 35 4C 20 40 00 E8 D2 00 00 00 6A 00 E8 BF 00 00 00 99 68 58 20 40 00 52 52 68 63 10 40 00 52 52 E8 DB 00 00 00 6A FF FF 35 48 20 40 00 E8 C2 00 00 00 E8 C8 FF FF FF BF 40 40 40 00 FF 35 4C 20 40 00 E8 A1 00 00 00 8B 0F 83 F9 00 74 B1 60 6A 00 6A 04 6A 01 51 FF 35 48 20 40 00 E8 75 00 00 00 61 60 BB 5C 20 40 00 6A 00 6A 01 53 51 FF 35 48 20 40 00 E8 75 00 00 00 61 A0 5C 20 40 00 8A 5F 05 3A C3 74 14 FF 35 4C 20 40 00 E8 4B 00 00 00 6A 03 E8 4A 00 00 00 EB A2 60 8D 5F 04 6A 00 6A 01 53 51 FF 35 48 20 40 00 E8 4B 00 00 00 61 83 C7 06 FF 35 4C 20 40 00 E8 1E 00 00 00 6A 03 E8 1D 00 00 00 E9 72 FF FF FF FF 25 70 30 40 00 FF 25 78  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_v0_90
{
strings:
		$a0 = { E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_0_22___0_23_beta
{
strings:
		$a0 = { AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 ?? 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_v0_99
{
strings:
		$a0 = { E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? 02 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? 02 00 00 00 00 00 ?? ?? 02 00 00 00 00 00 ?? ?? 02 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? 02 00 ?? ?? 02 00 ?? ?? 02 00 ?? ?? 02 00 77 ?? 02 00 ?? ?? 02 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? 00 00 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 00 00 ?? 00 00 ?? ?? 00 ?? ?? 00 00 ?? ?? ?? 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule CERBERUS_v2_0
{
strings:
		$a0 = { 9C 2B ED 8C ?? ?? 8C ?? ?? FA E4 ?? 88 ?? ?? 16 07 BF ?? ?? 8E DD 9B F5 B9 ?? ?? FC F3 A5  }

condition:
		$a0 at entrypoint
}
	
	
rule PluginToExe_v1_01____BoB___BobSoft
{
strings:
		$a0 = { E8 00 00 00 00 29 C0 5D 81 ED C6 41 40 00 50 8F 85 71 40 40 00 50 FF 95 A5 41 40 00 89 85 6D 40 40 00 FF 95 A1 41 40 00 50 FF 95 B5 41 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 B9 41 40 00 89 85 75 40 40 00 EB 6C 6A 01 8F 85 71 40 40 00 6A 58 6A 40 FF 95 A9 41 40 00 89 85 69 40 40 00 89 C7 68 00 08 00 00 6A 40 FF 95 A9 41 40 00 89 47 1C C7 07 58 00 00 00 C7 47 20 00 08 00 00 C7 47 18 01 00 00 00 C7 47 34 04 10 88 00 8D 8D B9 40 40 00 89 4F 0C 8D 8D DB 40 40 00 89 4F 30 FF B5 69 40 40 00 FF 95 95 41 40 00 FF 77 1C 8F 85 75 40 40 00 8B 9D 6D 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 75 40 40 00 6A 00 81 C3 ?? ?? 00 00 FF D3 83 C4 10 83 BD 71 40 40 00 00 74 10 FF 77 1C FF 95 AD 41 40 00 57 FF 95 AD 41 40 00 6A 00 FF 95 9D 41 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Horse_1776
{
strings:
		$a0 = { E8 ?? ?? 5D 83 ?? ?? 06 1E 26 ?? ?? ?? ?? BF ?? ?? 1E 0E 1F 8B F7 01 EE B9 ?? ?? FC F3 A6 1F 1E 07  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_SVKP_1_3x_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 00 00 00 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_UPX_0_89_6___1_02___1_05___1_24_____emadicius
{
strings:
		$a0 = { 60 BE 00 90 8B 00 8D BE 00 80 B4 FF 57 83 CD FF EB 3A 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 58 61 90 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule CDS_SS_1_0_beta1____CyberDoom
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED CA 47 40 00 FF 74 24 20 E8 D3 03 00 00 0B C0 0F 84 13 03 00 00 89 85 B8 4E 40 00 66 8C D8 A8 04 74 0C C7 85 8C 4E 40 00 01 00 00 00 EB 12 64 A1 30 00 00 00 0F B6 40 02 0A C0 0F 85 E8 02 00 00 8D 85 F6 4C 40 00 50 FF B5 B8 4E 40 00 E8 FC 03 00 00 0B C0 0F 84 CE 02 00 00 E8 1E 03 00 00 89 85 90 4E 40 00 8D 85 03 4D 40 00 50 FF B5 B8 4E 40 00 E8 D7 03 00 00 0B C0 0F 84 A9 02 00 00 E8 F9 02 00 00 89 85 94 4E 40 00 8D 85 12 4D 40 00 50  }

condition:
		$a0 at entrypoint
}
	
	
rule PureBasic_4_x____Neil_Hodgson
{
strings:
		$a0 = { 68 ?? ?? 00 00 68 00 00 00 00 68 ?? ?? ?? 00 E8 ?? ?? ?? 00 83 C4 0C 68 00 00 00 00 E8 ?? ?? ?? 00 A3 ?? ?? ?? 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? ?? ?? 00 A3  }

condition:
		$a0 at entrypoint
}
	
	
rule PENightMare_v1_3
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D B9 ?? ?? ?? ?? 80 31 15 41 81 F9  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C__v7_0___Basic__NET
{
strings:
		$a0 = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  }
	$a1 = { FF 25 00 20 00 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule RJoiner_by_Vaska__Sign_from_pinch_25_03_2007_17_00_
{
strings:
		$a0 = { E8 03 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 6C 10 40 00 FF 25 70 10 40 00 FF 25 74 10 40 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10  }

condition:
		$a0 at entrypoint
}
	
	
rule Crypto_Lock_v2_02__Eng_____Ryan_Thian
{
strings:
		$a0 = { 60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0  }
	$a1 = { 60 BE ?? 90 40 00 8D BE ?? ?? FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Pelles_C_2_80__2_90_EXE__X86_CRT_LIB_
{
strings:
		$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 ?? E8 ?? ?? ?? ?? 59 A3  }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptor_v2_0__Hide_EP______Vaska
{
strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 DC 20 ?? 00 F7 D1 83 F1 FF E8 00 00 00 00 F7 D1 83 F1 FF C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_Delphi_v3_0
{
strings:
		$a0 = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 55 8B EC 33 C0  }
	$a1 = { 55 8B EC 83 C4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ShellModify_0_1____pll621
{
strings:
		$a0 = { 55 8B EC 6A FF 68 98 66 41 00 68 3C 3D 41 00 64 A1 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule SecuROM_V7_X____Sony_DADC____Sign_By_fly___20080114
{
strings:
		$a0 = { 9C 9C 83 EC 1C C7 44 24 18 ?? ?? ?? ?? C7 44 24 14 BF 03 01 00 89 74 24 10 BE F0 ?? ?? ?? C1 4C 24 18 18 ?? 89 6C 24 0C 8B 2E 01 6C 24 18 ?? 83 C6 04 66 FF 4C 24 14 52 5A 75 ED 80 64 24 18 FE ?? 8B 74 24 1C C1 E1 00 8B 6C 24 18 89 74 24 18 8B 74 24 10 89 6C 24 1C C1 E2 00 8B 6C 24 0C 83 C4 18 9D ?? 74 12 81 04 24 ?? ?? ?? ?? ?? 81 04 24 C3 D1 FF 00 EB FA 6B 81 04 24 ?? ?? ?? ?? 0F AC F8 00 81 04 24 C2 04 00 3E FF 74 24 04 9D EB F5 EE 93 9D  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_k_kryptor_9_kryptor_a_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 ?? ?? ?? ?? 5E B9 00 00 00 00 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9  }

condition:
		$a0 at entrypoint
}
	
	
rule Program_Protector_XP_v1_0
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 81 C3 ?? ?? ?? ?? 8B 43 64 50  }

condition:
		$a0 at entrypoint
}
	
	
rule FileShield
{
strings:
		$a0 = { 50 1E EB ?? 90 00 00 8B D8  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__WATCOM_C_C___EXE______Anorganix
{
strings:
		$a0 = { E9 00 00 00 00 90 90 90 90 57 41 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_1
{
strings:
		$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_0
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_3
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C EB 07 8B 7B 02 57 83 C3 04 43 43 E9 52 FF FF FF 5F BB ?? ?? ?? ?? 47 8B 37 AF 57 FF 13 95 33 C0 AE 75 FD FE ?? 74 EF FE  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_2
{
strings:
		$a0 = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 ?? 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___vx_x_DLL
{
strings:
		$a0 = { 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 ?? ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? 00 ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FASM_v1_3x
{
strings:
		$a0 = { 6A ?? FF 15 ?? ?? ?? ?? A3  }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoiner_Small__build_031_032_____GlOFF
{
strings:
		$a0 = { 50 32 ?? 66 8B C3 58 E8 ?? FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule MESS_v1_20
{
strings:
		$a0 = { FA B9 ?? ?? F3 ?? ?? E3 ?? EB ?? EB ?? B6  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE_v2_00b
{
strings:
		$a0 = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 02 00 72 ?? B4 09 BA ?? ?? CD 21 B8 01 4C CD 21 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 59 2D ?? ?? 8E D0 51 2D ?? ?? 8E C0 50 B9  }

condition:
		$a0 at entrypoint
}
	
	
rule Pe123__v2006_4_4
{
strings:
		$a0 = { 8B C0 EB 01 34 60 EB 01 2A 9C EB 02 EA C8 E8 0F 00 00 00 EB 03 3D 23 23 EB 01 4A EB 01 5B C3 8D 40 00 53 EB 01 6C EB 01 7E EB 01 8F E8 15 01 00 00 50 E8 67 04 00 00 EB 01 9A 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10  }

condition:
		$a0 at entrypoint
}
	
	
rule Wise_Installer_Stub_v1_10_1029_1
{
strings:
		$a0 = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 E8 8A 08 80 F9 2F 74 2B 84 C9 74 1F 80 F9 3D 74 1A 8A 48 01 40 EB F1 33 F6 84 C9 74 D6 80 F9 20 74  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_18_Dll__aPlib_0_43_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 5C 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule Nullsoft_PIMP_Install_System_v1_3x
{
strings:
		$a0 = { 55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD  }

condition:
		$a0 at entrypoint
}
	
	
rule Simple_UPX_Cryptor_v30_4_2005_rule__One_layer_encryption______MANtiCORE
{
strings:
		$a0 = { 60 B8 ?? ?? ?? 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDote_V1_2_DLL_Demo____SIS_Team_____Sign_By_fly
{
strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 08 32 90 90 90 90 90 90 90 90 90 90 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_3_4____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 03  }

condition:
		$a0 at entrypoint
}
	
	
rule ExeSplitter_1_3__Split_Crypt_Method_____Bill_Prisoner___TPOC
{
strings:
		$a0 = { E8 00 00 00 00 5D 81 ED 05 10 40 00 B9 ?? ?? ?? ?? 8D 85 1D 10 40 00 80 30 66 40 E2 FA 8F 98 67 66 66 ?? ?? ?? ?? ?? ?? ?? 66  }

condition:
		$a0 at entrypoint
}
	
	
rule SimbiOZ_Poly_2_1____Extranger
{
strings:
		$a0 = { 55 50 8B C4 83 C0 04 C7 00 ?? ?? ?? ?? 58 C3 90  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_Unknown__DLL_________Dwing
{
strings:
		$a0 = { 60 E8 09 00 00 00 17 CD 00 00 E9 06 02  }

condition:
		$a0 at entrypoint
}
	
	
rule Enigma_Protector_V1_1X_V1_5X____Sukhov_Vladimir___Serge_N__Markin_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 00 10 40 00 E8 01 00 00 00 9A 83 C4 10 8B E5 5D E9  }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptor_v2_0_____Vaska
{
strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? 02 00 00 F7 D1 83 F1 FF 59 BA 32 21 ?? 00 F7 D1 83 F1 FF F7 D1 83 F1 FF 80 02 E3 F7 D1 83 F1 FF C0 0A 05 F7 D1 83 F1 FF 80 02 6F F7 D1 83 F1 FF 80 32 A4 F7 D1 83 F1 FF 80 02 2D F7 D1 83 F1 FF 42 49 85 C9 75 CD 1C 4F 8D 5B FD 62 1E 1C 4F 8D 5B FD 4D 9D B9 ?? ?? ?? 1E 1C 4F 8D 5B FD 22 1C 4F 8D 5B FD 8E A2 B9 B9 E2 83 DB E2 E5 4D CD 1E BF 60 AB 1F 4D DB 1E 1E 3D 1E 92 1B 8E DC 7D EC A4 E2 4D E5 20 C6 CC B2 8E EC 2D 7D DC 1C 4F 8D 5B FD 83 56 8E E0 3A 7D D0 8E 9D 6E 7D D6 4D 25 06 C2 AB 20 CC 3A 4D 2D 9D 6B 0B 81 45 CC 18 4D 2D 1F A1 A1 6B C2 CC F7 E2 4D 2D 9E 8B 8B CC DE 2E 2D F7 1E AB 7D 45 92 30 8E E6 B9 7D D6 8E 9D 27 DA FD FD 1E 1E 8E DF B8 7D CF 8E A3 4D 7D DC 1C 4F 8D 5B FD 33 D7 1E 1E 1E A6 0B 41 A1 A6 42 61 6B 41 6B 4C 45 1E 21 F6 26 BC E2 62 1E 62 1E 62 1E 23 63 59 ?? 1E 62 1E 62 1E 33 D7 1E 1E 1E 85 6B C2 41 AB C2 9F 23 6B C2 41 A1 1E C0 FD F0 FD 30 20 33 9E 1E 1E 1E 85 A2 0B 8B C2 27 41 EB A1 A2 C2 1E C0 FD F0 FD 30 62 1E 33 7E 1E 1E 1E C6 2D 42 AB 9F 23 6B C2 41 A1 1E C0 FD F0 FD 30 C0 FD F0 8E 1D 1C 4F 8D 5B FD E0 00 33 5E 1E 1E 1E BF 0B EC C2 E6 42 A2 C2 45 1E C0 FD F0 FD 30 CE 36 CC F2 1C 4F 8D 5B FD  }

condition:
		$a0 at entrypoint
}
	
	
rule DEF_v1_00__Eng_____bart_xt
{
strings:
		$a0 = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PPC_PROTECT_V1_1X____Alexey_Gorchakov_____Sign_By_fly
{
strings:
		$a0 = { FF 5F 2D E9 20 00 9F E5 00 00 90 E5 18 00 8F E5 18 00 9F E5 00 00 90 E5 10 00 8F E5 01 00 A0 E3 00 00 00 EB 02 00 00 EA 04 F0 1F E5  }

condition:
		$a0 at entrypoint
}
	
	
rule PECompact_v0_90
{
strings:
		$a0 = { EB 06 68 ?? ?? 40 00 C3 9C 60 BD ?? ?? 00 00 B9 02 00 00 00 B0 90 8D BD 7A 42 40 00 F3 AA 01 AD D9 43 40 00 FF B5  }

condition:
		$a0 at entrypoint
}
	
	
rule NsPack_v3_1____North_Star
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00  }

condition:
		$a0 at entrypoint
}
	
	
rule _pirit_v1_5
{
strings:
		$a0 = { 5B 24 55 50 44 FB 32 2E 31 5D  }

condition:
		$a0 at entrypoint
}
	
	
rule PECompact_v0_94
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v1_90c
{
strings:
		$a0 = { 55 8B EC 6A FF 68 10 F2 40 00 68 74 9D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v1_90a
{
strings:
		$a0 = { 55 8B EC 64 FF 68 10 F2 40 00 68 14 9B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Stealth_PE_v1_1
{
strings:
		$a0 = { BA ?? ?? ?? 00 FF E2 BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 03 B8 ?? ?? ?? ?? 89 02 83 C2 FD FF E2  }

condition:
		$a0 at entrypoint
}
	
	
rule Nullsoft_Install_System_v2_0b4
{
strings:
		$a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00 68 E4 91 40 00 56 FF D3 E8 7C FF FF FF 85 C0 0F 84 59 01 00 00 BE E0 66 42 00 56 FF 15 68 70 40 00 68 D8 91 40 00 56 E8 FE 27 00 00 57 FF 15 BC 70 40 00 BE 00 C0 42 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 C0 42 00 22 A3 E0 6E 42 00 8B C6 75 0A C6 44 24 13 22 B8 01 C0 42 00 8B 3D 10 72 40 00 EB 09 3A 4C 24 13 74 09 50 FF D7 8A 08 84 C9 75 F1 50 FF D7 8B F0 89 74 24 1C EB 05 56 FF D7 8B F0 80 3E 20 74 F6 80 3E 2F 75 44 46 80 3E 53 75 0C 8A 46 01 0C 20 3C 20 75 03 83 CD 02 81 3E 4E 43 52  }
	$a1 = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 40 00 03 C6 50 E8 78 29 00 00 56 E8 47 2B 00 00 6A 00 56 FF D3 56 57 E8 EA 25 00 00 85 C0 75 0D C7 44 24 14 58 91 40 00 E9 72 02 00 00 57 FF 15 24 71 40 00 68 EC 91 40 00 57 E8 43  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule IcebergLock_Protector_V3_10_1_36____Iceberg_Software_Lab_____Sign_By_fly___20080217
{
strings:
		$a0 = { E8 D7 FF FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 00 00 72 F9 C3 8D 40 00 55 8B EC 33 C0 55 ?? ?? ?? ?? ?? 64 FF 30 64 89 20 33 C0 5A 59 59 64 89 10 ?? ?? ?? ?? ?? C3 E9 50 CD FD FF EB F8 5D C3 1E 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 8B EC 83 ?? ?? B8 ?? ?? ?? ?? E8 B8 EF FD FF E8 2F DF FF FF B8 ?? ?? ?? ?? E8 71 FE FF FF E8 18 D1 FD FF  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_Spalsher_1_x_3_x_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 9C 60 8B 44 24 24 E8 00 00 00 00 5D 81 ED 00 00 00 00 50 E8 ED 02 00 00 8C C0 0F 84  }

condition:
		$a0 at entrypoint
}
	
	
rule Matrix_Dongle____TDi_GmbH_____Sign_By_fly
{
strings:
		$a0 = { E8 00 00 00 00 E8 00 00 00 00 59 5A 2B CA 2B D1 E8 1A FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v4_x
{
strings:
		$a0 = { 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Unnamed_Scrambler_1_3B____p0ke
{
strings:
		$a0 = { 55 8B EC B9 08 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 98 56 00 10 E8 48 EB FF FF 33 C0 55 68 AC 5D 00 10 64 FF 30 64 89 20 6A 00 68 BC 5D 00 10 68 C4 5D 00 10 6A 00 E8 23 EC FF FF E8 C6 CE FF FF 6A 00 68 BC 5D 00 10 68 ?? ?? ?? ?? 6A 00 E8 0B EC FF FF E8 F2 F4 FF FF B8 08 BC 00 10 33 C9 BA 04 01 00 00 E8 C1 D2 FF FF 6A 00 68 BC 5D 00 10 68 E4 5D 00 10 6A 00 E8 E2 EB FF FF 68 04 01 00 00 68 08 BC 00 10 6A 00 FF 15 68 77 00 10 6A 00 68 BC 5D 00 10 68 FC 5D 00 10 6A 00 E8 BD EB FF FF BA 10 5E 00 10 B8 70 77 00 10 E8 CA F3 FF FF 85 C0 0F 84 F7 05 00 00 BA 74 77 00 10 8B 0D 70 77 00 10 E8 FE CD FF FF 6A 00  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE_Stealth_v2_76____WebToolMaster
{
strings:
		$a0 = { EB 65 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 59 4F 55 52 20 41 44 20 48 45 52 45 21 50 69 52 41 43 59 20 69 53 20 41  }

condition:
		$a0 at entrypoint
}
	
	
rule BeRoEXEPacker_v1_00_DLL_rule__LZBRS_____BeRo___Farbrausch
{
strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 ?? ?? ?? ?? 72 03 A4 EB F2 E8 ?? ?? ?? ?? 8D 51 FF E8 ?? ?? ?? ?? 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33  }

condition:
		$a0 at entrypoint
}
	
	
rule nPack_V1_1_200_2006_Beta____NEOx_rule__uinC_
{
strings:
		$a0 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? ?? E8 5E 00 00 00 E8 EC 01 00 00 E8 F8 06 00 00 E8 03 06 00 00 A1 3C ?? ?? ?? C7 05 40 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Splice_1_1___by_Tw1sted_L0gic
{
strings:
		$a0 = { 68 00 1A 40 00 E8 EE FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 01 00 00 00 ?? ?? ?? ?? ?? ?? 50 72 6F 6A 65 63 74 31 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 06 00 00 00 AC 29 40 00 07 00 00 00 BC 28 40 00 07 00 00 00 74 28 40 00 07 00 00 00 2C 28 40 00 07 00 00 00 08 23 40 00 01 00 00 00 38 21 40 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 8C 21 40 00 08 ?? 40 00 01 00 00 00 AC 19 40 00 00 00 00 00 00 00 00 00 00 00 00 00 AC 19 40 00 4F 00 43 00 50 00 00 00 E7 AF 58 2F 9A 4C 17 4D B7 A9 CA 3E 57 6F F7 76  }

condition:
		$a0 at entrypoint
}
	
	
rule yoda_s_Protector_V1_02____Ashkbiz_Danehkar_____Sign_By_fly
{
strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 23 3F 42 00 8B D5 81 C2 72 3F 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 3A 66 42 00 81 E9 1D 40 42 00 8B D5 81 C2 1D 40 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 C3 1F 00 00 33 C0 64 FF 30 64 89 20 43 CC C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Inbuild_v1_0_rule__hard_
{
strings:
		$a0 = { B9 ?? ?? BB ?? ?? 2E ?? ?? 2E ?? ?? 43 E2  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_00
{
strings:
		$a0 = { 55 8B EC 6A FF 68 00 02 41 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_01
{
strings:
		$a0 = { 55 8B EC 6A FF 68 08 02 41 00 68 04 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule diPacker_V1_X____diProtector_Software_____Sign_By_fly
{
strings:
		$a0 = { 0F 00 2D E9 01 00 A0 E3 68 01 00 EB 8C 00 00 EB 2B 00 00 EB 00 00 20 E0 1C 10 8F E2 8E 20 8F E2 00 30 A0 E3 67 01 00 EB 0F 00 BD E8 00 C0 8F E2 00 F0 9C E5  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE_v1_00c__1_
{
strings:
		$a0 = { 2E 8C 1E ?? ?? 8B 1E ?? ?? 8C DA 81 C2 ?? ?? 3B DA 72 ?? 81 EB ?? ?? 83 EB ?? FA 8E D3 BC ?? ?? FB FD BE ?? ?? 8B FE  }

condition:
		$a0 at entrypoint
}
	
	
rule Ionic_Wind_Software
{
strings:
		$a0 = { 9B DB E3 9B DB E2 D9 2D 00 ?? ?? 00 55 89 E5 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule SoftWrap
{
strings:
		$a0 = { 52 53 51 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 36 ?? ?? ?? E8 ?? 01 ?? ?? 60 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F  }

condition:
		$a0 at entrypoint
}
	
	
rule ACProtect_V1_3X____risco
{
strings:
		$a0 = { 60 50 E8 01 00 00 00 75 83  }

condition:
		$a0 at entrypoint
}
	
	
rule MicroJoiner_1_7____coban2k
{
strings:
		$a0 = { BF 00 10 40 00 8D 5F 21 6A 0A 58 6A 04 59 60 57 E8 8E 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE32Pack_v1_39
{
strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED EC 8D 40  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE32Pack_v1_38
{
strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED DC 8D 40  }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtect_V2_X_Registered____Alexey_Solodovnikov_____Sign_By_fly
{
strings:
		$a0 = { 68 01 ?? ?? ?? E8 01 00 00 00 C3 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Packman_v0_0_0_1
{
strings:
		$a0 = { 60 E8 00 00 00 00 58 8D A8 ?? ?? FF FF 8D 98 ?? ?? ?? FF 8D B0 74 01 00 00 8D 4E F6 48 C6 40 FB E9 8D 93 ?? ?? ?? 00 2B D0 89 50 FC 8D 93 54 01 00 00 E9 9A 00 00 00 83 C2 04 03 FB 51 D1 C7 D1 EF 0F 83 84 00 00 00 53 55 52 B2 80 8B D9 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 3D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 97 33 C9 41 FF D3 13 C9 FF D3 72 F8 C3 5A 5D 5B EB 05 AD 8B C8 F3 A4 59 8B 3A 85 FF 0F 85 5C FF FF FF 8D B3 ?? 20 ?? 00 EB 3D 8B 46 0C 03 C3 50 FF 55 00 56 8B 36 0B F6 75 02 8B F7 03 F3 03 FB EB 1B D1 C1 D1 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__PENinja_1_31______Anorganix
{
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__XPEH_4768
{
strings:
		$a0 = { E8 ?? ?? 5B 81 ?? ?? ?? 50 56 57 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? ?? B8 01 00 50 B8 ?? ?? 50 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE32Pack_v1_36
{
strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED CC 8D 40  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_PE_Crypt_1_02_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44  }

condition:
		$a0 at entrypoint
}
	
	
rule ExeLock_v1_00
{
strings:
		$a0 = { 06 8C C8 8E C0 BE ?? ?? 26 ?? ?? 34 ?? 26 ?? ?? 46 81 ?? ?? ?? 75 ?? 40 B3 ?? B3 ?? F3  }

condition:
		$a0 at entrypoint
}
	
	
rule PEiD_Bundle_V1_00____BoB___BobSoft
{
strings:
		$a0 = { 60 E8 21 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Lock_NT_v2_02c
{
strings:
		$a0 = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_v0_36_beta____Dwing
{
strings:
		$a0 = { BE E0 11 ?? ?? FF 36 E9 C3 00 00 00 48 01 ?? ?? 0B 01 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 82 8E FE FF FF 58 8B 4E 40 5F E3  }

condition:
		$a0 at entrypoint
}
	
	
rule EmbedPE_1_13____cyclotron
{
strings:
		$a0 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 B8 5E 2D C6 DA FD 48 63 05 3C 71 B8 5E 97 7C 36 7E 32 7C 08 4F 06 51 64 10 A3 F1 4E CF 25 CB 80 D2 99 54 46 ED E1 D3 46 86 2D 10 68 93 83 5C 46 4D 43 9B 8C D6 7C BB 99 69 97 71 2A 2F A3 38 6B 33  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_V0_10_V0_11____Dwing
{
strings:
		$a0 = { BE ?? ?? ?? ?? AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 ?? F3 AB C1 E0 ?? B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C ?? 73 ?? B0 ?? 3C ?? 72 02 2C ?? 50 0F B6 5F FF C1 E3 ?? B3 ?? 8D 1C 5B 8D ?? ?? ?? ?? ?? ?? B0 ?? 67 E3 29 8B D7 2B 56 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF D5  }

condition:
		$a0 at entrypoint
}
	
	
rule BobSoft_Mini_Delphi____BoB___BobSoft
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8  }
	$a1 = { 55 8B EC 83 C4 F0 53 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8 ?? ?? ?? ?? E8  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule N_Joy_1_3____NEX
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 48 36 40 00 E8 54 EE FF FF 6A 00 68 D8 2B 40 00 6A 0A 6A 00 E8 2C EF FF FF E8 23 E7 FF FF 8D 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_V0_20____Dwing_____Sign_By_fly___20080321
{
strings:
		$a0 = { BE ?? ?? ?? ?? AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A ?? ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 ?? ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 01 67 E3 29 8B D7 2B 55 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 56 08 33 C9 E9 07 01 00 00 8B 5D 0C 83 C2 30 FF 16 73 53 83 C2 30 FF 16 72 1B 83 C2 30 FF 16 72 2B 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 45 0C B1 80 8A 00 EB CF 83 C2 60 FF 16 87 5D 10 73 0D 83 C2 30 FF 16 87 5D 14 73 03 87 5D 18 3C 07 B0 08 72 02 B0 0B 50 53 8D 95 7C 07 00 00 FF 56 0C 5B 91 E9 9C 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE32Pack_v1_3x
{
strings:
		$a0 = { 3B ?? 74 02 81 83 55 3B ?? 74 02 81 ?? 53 3B ?? 74 01 ?? ?? ?? ?? ?? 02 81 ?? ?? E8 ?? ?? ?? ?? 3B 74 01 ?? 5D 8B D5 81 ED  }

condition:
		$a0 at entrypoint
}
	
	
rule WinUpack_v0_39_final____By_Dwing__c_2005__h1_
{
strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 39 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Dual_s_eXe_Encryptor_1_0b____Dual
{
strings:
		$a0 = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E 00 00 00 8D 85 3A 04 00 00 89 28 33 FF 8D 85 80 03 00 00 8D 8D 3A 04 00 00 2B C8 8B 9D 8A 04 00 00 E8 24 02 00 00 8D 9D 58 03 00 00 8D B5 7F 03 00 00 46 80 3E 00 74 24 56 FF 95 58 05 00 00 46 80 3E 00 75 FA 46 80 3E 00 74 E7 50 56 50 FF 95 5C 05 00 00 89 03 58 83 C3 04 EB E3 8D 85 69 02 00 00 FF D0 8D 85 56 04 00 00 50 68 1F 00 02 00 6A 00 8D 85 7A 04 00 00 50  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_0_0____Obsidium_Software
{
strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 ?? 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule LaunchAnywhere_v4_0_0_1
{
strings:
		$a0 = { 55 89 E5 53 83 EC 48 55 B8 FF FF FF FF 50 50 68 E0 3E 42 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 C0 69 44 00 E8 E4 80 FF FF 59 E8 4E 29 00 00 E8 C9 0D 00 00 85 C0 75 08 6A FF E8 6E 2B 00 00 59 E8 A8 2C 00 00 E8 23 2E 00 00 FF 15 4C C2 44 00 89 C3 EB 19 3C 22 75 14 89 C0 8D 40 00 43 8A 03 84 C0 74 04 3C 22 75 F5 3C 22 75 01 43 8A 03 84 C0 74 0B 3C 20 74 07 3C 09 75 D9 EB 01 43 8A 03 84 C0 74 04 3C 20 7E F5 8D 45 B8 50 FF 15 E4 C1 44 00 8B 45 E4 25 01 00 00 00 74 06 0F B7 45 E8 EB 05 B8 0A 00 00 00 50 53 6A 00 6A 00 FF 15 08 C2 44 00 50 E8 63 15 FF FF 50 E8 EE 2A 00 00 59 8D 65 FC 5B  }

condition:
		$a0 at entrypoint
}
	
	
rule PROTECT__EXE_COM_v6_0
{
strings:
		$a0 = { 1E B4 30 CD 21 3C 02 73 ?? CD 20 BE ?? ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule SecurePE_V1_X____www_deepzone_org_____Sign_By_fly
{
strings:
		$a0 = { 8B 04 24 E8 00 00 00 00 5D 81 ED 4C 2F 40 00 89 85 61 2F 40 00 8D 9D 65 2F 40 00 53 C3 00 00 00 00 8D B5 BA 2F 40 00 8B FE BB 65 2F 40 00 B9 C6 01 00 00 AD 2B C3 C1 C0 03 33 C3 AB 43 81 FB 8E 2F 40 00 75 05 BB 65 2F 40 00 E2 E7 89 AD 1A 31 40 00 89 AD 55 34 40 00 89 AD 68 34 40 00 8D 85 BA 2F 40 00 50 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule BeRoEXEPacker_v1_00_rule__LZMA_____BeRo___Farbrausch
{
strings:
		$a0 = { 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 04 00 00 00 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8  }

condition:
		$a0 at entrypoint
}
	
	
rule VProtector_V1_0X____vcasm_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 E8 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 05 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FACRYPT_v1_0
{
strings:
		$a0 = { B9 ?? ?? B3 ?? 33 D2 BE ?? ?? 8B FE AC 32 C3 AA 49 43 32 E4 03 D0 E3  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_Delphi_v6_0
{
strings:
		$a0 = { 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? FF A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? E8  }
	$a1 = { 55 8B EC 83 C4 F0 B8 ?? ?? 45 00 E8 ?? ?? ?? FF A1 ?? ?? 45 00 8B 00 E8 ?? ?? FF FF 8B 0D  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule StarForce_V3_X_DLL____StarForce_Copy_Protection_System
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_v1_25__Delphi__Stub
{
strings:
		$a0 = { 60 BE 00 ?? ?? 00 8D BE 00 ?? ?? FF  }

condition:
		$a0 at entrypoint
}
	
	
rule PACKWIN_v1_01p
{
strings:
		$a0 = { 8C C0 FA 8E D0 BC ?? ?? FB 06 0E 1F 2E ?? ?? ?? ?? 8B F1 4E 8B FE 8C DB 2E ?? ?? ?? ?? 8E C3 FD F3 A4 53 B8 ?? ?? 50 CB  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_Delphi_v6_0_KOL
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF A1 ?? 72 40 00 33 D2 E8 ?? ?? FF FF A1 ?? 72 40 00 8B 00 83 C0 14 E8 ?? ?? FF FF E8 ?? ?? FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v1_60a
{
strings:
		$a0 = { 55 8B EC 6A FF 68 98 71 40 00 68 48 2D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Inno_Setup_Module_v2_0_18
{
strings:
		$a0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 73 71 FF FF E8 DA 85 FF FF E8 81 A7 FF FF E8 C8  }

condition:
		$a0 at entrypoint
}
	
	
rule BopCrypt_v1_0
{
strings:
		$a0 = { 60 BD ?? ?? ?? ?? E8 ?? ?? 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule MicroDog_Win32Shell_V4_0_9_3____SafeNet_____Sign_By_fly
{
strings:
		$a0 = { 60 55 8B EC 81 EC 34 04 00 00 53 56 57 C6 85 B8 FE FF FF 00 C6 85 B9 FE FF FF 00 C6 85 BA FE FF FF 00 C6 85 BB FE FF FF 00 8D BD BC FE FF FF 33 C0 B9 3F 00 00 00 F3 AB C6 85 E8 FC FF FF 00 C6 85 E9 FC FF FF 00 C6 85 EA FC FF FF 00 C6 85 EB FC FF FF 00 8D BD EC FC FF FF 33 C0 B9 3F 00 00 00 F3 AB C7 85 10 FE FF FF A5 A5 00 00 66 C7 85 08 FE FF FF 0A 00 E9 13 09 00 00 90 68 00 10 00 00 E8 B8 F5 FF FF 83 C4 04 89 45 D0 83 7D D0 00 75 05 E9 C1 11 00 00 68 00 10 00 00 A1 ?? ?? ?? ?? 50 8B 45 D0 50 E8 FF F6 FF FF 83 C4 0C A1 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 89 85 34 FE FF FF 8B 85 34 FE FF FF 89 45 CC E9 CE 0E 00 00 E9 36 11 00 00 E9 3D 11 00 00 E9 38 11 00 00 66 C7 45 EC 00 00 EB 04 66 FF 45 EC 8B 45 EC 25 FF FF 00 00 83 F8 03 0F 8D DF 00 00 00 8B 45 EC 25 FF FF 00 00 8B 4D EC 81 E1 FF FF 00 00 0F AF C1 8B 4D EC 81 E1 FF FF 00 00 0F AF C1 8B 4D EC 81 E1 FF FF 00 00 0F AF C1 83 C0 07 89 85 EC FB FF FF EB 7E  }

condition:
		$a0 at entrypoint
}
	
	
rule InstallShield_Custom
{
strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? 41 00 8B F0 85 F6 75 08 6A FF FF 15 ?? ?? 41 00 8A 06 57 8B 3D ?? ?? 41 00 3C 22 75 1B 56 FF D7 8B F0 8A 06 3C 22 74 04 84 C0 75 F1 80 3E 22 75 15 56 FF D7 8B  }

condition:
		$a0 at entrypoint
}
	
	
rule REALbasic
{
strings:
		$a0 = { 55 89 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule NFO_v1_0
{
strings:
		$a0 = { 8D 50 12 2B C9 B1 1E 8A 02 34 77 88 02 42 E2 F7 C8 8C  }

condition:
		$a0 at entrypoint
}
	
	
rule Virogen_s_PE_Shrinker_v0_14
{
strings:
		$a0 = { 9C 55 E8 ?? ?? ?? ?? 87 D5 5D 60 87 D5 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 57 56 AD 0B C0 74  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Lock_v1_06
{
strings:
		$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 4B 45  }

condition:
		$a0 at entrypoint
}
	
	
rule Apex_c_beta____500mhz
{
strings:
		$a0 = { 68 ?? ?? ?? ?? B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACK_v3_03
{
strings:
		$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 BB ?? ?? 53  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__ARCV_4
{
strings:
		$a0 = { E8 00 00 5D 81 ED 06 01 81 FC 4F 50 74 0B 8D B6 86 01 BF 00 01 57 A4 EB 11 1E 06  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_PACK_0_99
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 80 BD E0 04 00 00 01 0F 84 F2  }

condition:
		$a0 at entrypoint
}
	
	
rule Nullsoft_Install_System_v1_98
{
strings:
		$a0 = { 83 EC 0C 53 56 57 FF 15 2C 81 40  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Password_v0_2_SMT_SMF
{
strings:
		$a0 = { E8 04 ?? ?? ?? 8B EC 5D C3 33 C0 5D 8B FD 81 ED 33 26 40 ?? 81 EF ?? ?? ?? ?? 83 EF 05 89 AD 88 27 40 ?? 8D 9D 07 29 40 ?? 8D B5 62 28 40 ?? 46 80  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_0_X____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B ?? ?? ?? EB 04 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3  }

condition:
		$a0 at entrypoint
}
	
	
rule y0da_s_Crypter_v1_2
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC  }

condition:
		$a0 at entrypoint
}
	
	
rule beria_v0_07_public_WIP_____symbiont
{
strings:
		$a0 = { 83 EC 18 53 8B 1D 00 30 ?? ?? 55 56 57 68 30 07 00 00 33 ED 55 FF D3 8B F0 3B F5 74 0D 89 AE 20 07 00 00 E8 88 0F 00 00 EB 02 33 F6 6A 10 55 89 35 30 40 ?? ?? FF D3 8B F0 3B F5 74 09 89 2E E8 3C FE FF FF EB 02 33 F6 6A 18 55 89 35 D8 43 ?? ?? FF D3 8B F0  }

condition:
		$a0 at entrypoint
}
	
	
rule y0da_s_Crypter_v1_1
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 8A 1C 40 00 B9 9E 00 00 00 8D BD 4C 23 40 00 8B F7 33  }

condition:
		$a0 at entrypoint
}
	
	
rule N_Joy_1_0____NEX
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 9C 3B 40 00 E8 8C FC FF FF 6A 00 68 E4 39 40 00 6A 0A 6A 00 E8 40 FD FF FF E8 EF F5 FF FF 8D 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Spanz
{
strings:
		$a0 = { E8 00 00 5E 81 EE ?? ?? 8D 94 ?? ?? B4 1A CD 21 C7 84  }

condition:
		$a0 at entrypoint
}
	
	
rule MicroJoiner_1_1____coban2k
{
strings:
		$a0 = { BE 0C 70 40 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11  }

condition:
		$a0 at entrypoint
}
	
	
rule Anslym_Crypter
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 38 17 05 10 E8 5A 45 FB FF 33 C0 55 68 21 1C 05 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 E8 85 4C FB FF 6A 00 E8 0E 47 FB FF 6A 0A E8 27 49 FB FF E8 EA 47 FB FF 6A 0A 68 30 1C 05 10 A1 60 56 05 10 50 E8 68 47 FB FF 8B D8 85 DB 0F 84 B6 02 00 00 53 A1 60 56 05 10 50 E8 F2 48 FB FF 8B F0 85 F6 0F 84 A0 02 00 00 E8 F3  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE_Stealth_v2_73
{
strings:
		$a0 = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 EB 16 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 60 90 E8 00 00 00 00 5D 81 ED F0 27 40 00 B9 15 00 00 00 83 C1 05 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 77 0C 00 00 90 8D BD 61 28 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE_Stealth_v2_71
{
strings:
		$a0 = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED B0 27 40  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE_Stealth_v2_74
{
strings:
		$a0 = { EB 00 EB 17 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 60 90 E8 00 00 00 00 5D 81 ED C4 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 91 0C 00 00 90 8D BD 38 28 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_2_5xx____Jtit
{
strings:
		$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D ?? 1A 00 00 B9 ?? 1A 00 00 BA ?? 1B 00 00 BE 00 10 00 00 BF ?? 53 00 00 BD ?? 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? ?? 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10 ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3B F1 7C 04 3B F2 7C 02 89 2E 83 C6 04 3B F7 7C E3 58 50 68 00 00 40 00 68 80 5A  }

condition:
		$a0 at entrypoint
}
	
	
rule ExeTools_v2_1_Encruptor_by_DISMEMBER
{
strings:
		$a0 = { E8 ?? ?? 5D 83 ?? ?? 1E 8C DA 83 ?? ?? 8E DA 8E C2 BB ?? ?? BA ?? ?? 85 D2 74  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__CD_Cops_II______Anorganix
{
strings:
		$a0 = { 53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Pi_Cryptor_1_0___by_Scofield
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 57 31 C0 89 45 EC B8 40 1E 06 00 E8 48 FA FF FF 33 C0 55 68 36 1F 06 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 31 C0 E8 4E F4 FF FF 8B 45 EC E8 F6 F7 FF FF 50 E8 CC FA FF FF 8B D8 83 FB FF 74 4E 6A 00 53 E8 CD FA FF FF 8B F8 81 EF AC 26 00 00 6A 00 6A 00 68 AC 26 00 00 53 E8 DE FA FF FF 89 F8 E8 E3 F1 FF FF 89 C6 6A 00 68 28 31 06 00 57 56 53 E8 AE FA FF FF 53 E8 80 FA FF FF 89 FA 81 EA 72 01 00 00 8B C6 E8 55 FE FF FF 89 C6 89 F0 09 C0 74 05 E8 A8 FB FF FF 31 C0 5A 59 59 64 89 10 68 3D 1F 06 00 8D 45 EC E8 C3 F6 FF FF C3  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Crypt_1_5____BitShape_Software
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 55 20 40 00 B9 7B 09 00 00 8D BD 9D 20 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Embedded_V2_422_V2_428____Jitit_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D 9B 1A 00 00 B9 84 1A 00 00 BA 14 1B 00 00 BE 00 10 00 00 BF B0 53 00 00 BD E0 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? 81 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Backfont_900
{
strings:
		$a0 = { E8 ?? ?? B4 30 CD 21 3C 03 ?? ?? B8 ?? ?? BA ?? ?? CD 21 81 FA ?? ?? ?? ?? BA ?? ?? 8C C0 48 8E C0 8E D8 80 ?? ?? ?? 5A ?? ?? 03 ?? ?? ?? 40 8E D8 80 ?? ?? ?? 5A ?? ?? 83  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____bart_xt_____Watcom_C_C___EXE_
{
strings:
		$a0 = { EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_PC_Guard_4_xx_____emadicius
{
strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 58 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Imploder_v1_04_____BoB___BobSoft
{
strings:
		$a0 = { 60 E8 A0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44  }

condition:
		$a0 at entrypoint
}
	
	
rule ReversingLabsProtector_0_7_4_beta____Ap0x
{
strings:
		$a0 = { 68 00 00 41 00 E8 01 00 00 00 C3 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACK_v3_02__v3_02a__v3_04__Relocations_pack_
{
strings:
		$a0 = { BE ?? ?? BF ?? ?? B9 ?? ?? 8C CD 81 ED ?? ?? 8B DD 81 EB ?? ?? 8B D3 FC FA 1E 8E DB 01 15 33 C0 2E AC  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack____Ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 2C 0A 00 00 8D 9D 22 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 CD 09 00 00 89 85 ?? ?? ?? ?? EB 14 60 FF B5 14 0A  }
	$a1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 EB 09 00 00 89 85 ?? ?? ?? ?? EB 14 60 FF B5 3A 0A  }
	$a2 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 ?? ?? ?? ?? EB 03 ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 9B 0A  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule VProtector_V1_0_rule__Build_2004_12_13__test_____vcasm
{
strings:
		$a0 = { 55 8B EC 6A FF 68 1A 89 40 00 68 56 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_v0_85f
{
strings:
		$a0 = { 60 E8 02 00 00 00 CD 20 E8 00 00 00 00 5E 2B C9 58 74 02  }

condition:
		$a0 at entrypoint
}
	
	
rule LCC_Win32_v1_x
{
strings:
		$a0 = { 64 A1 ?? ?? ?? ?? 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 ?? 50  }

condition:
		$a0 at entrypoint
}
	
	
rule XPack_1_67
{
strings:
		$a0 = { B8 8C D3 15 33 75 81 3E E8 0F 00 9A E8 F9 FF 9A 9C EB 01 9A 59 80 CD 01 51 9D EB  }

condition:
		$a0 at entrypoint
}
	
	
rule HACKSTOP_v1_10__v1_11
{
strings:
		$a0 = { B4 30 CD 21 86 E0 3D ?? ?? 73 ?? B4 2F CD 21 B0 ?? B4 4C CD 21 50 B8 ?? ?? 58 EB  }

condition:
		$a0 at entrypoint
}
	
	
rule UPXcrypter____archphase_NWC
{
strings:
		$a0 = { BF ?? ?? ?? 00 81 FF ?? ?? ?? 00 74 10 81 2F ?? 00 00 00 83 C7 04 BB 05 ?? ?? 00 FF E3 BE ?? ?? ?? 00 FF E6 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v1_72___v1_73
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 ?? ?? 68 F4 86 ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule NX_PE_Packer_v1_0
{
strings:
		$a0 = { FF 60 FF CA FF 00 BA DC 0D E0 40 00 50 00 60 00 70 00 80 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PEiD_Bundle_V1_02____BoB___BobSoft
{
strings:
		$a0 = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44  }

condition:
		$a0 at entrypoint
}
	
	
rule PECompact_v0_92
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD A5 4F 40 ?? F3 AA 01 AD 04 51 40 ?? FF B5  }

condition:
		$a0 at entrypoint
}
	
	
rule MinGW_v3_2_x___mainCRTStartup_
{
strings:
		$a0 = { 55 89 E5 83 EC 08 6A 00 6A 00 6A 00 6A 00 E8 0D 00 00 00 B8 00 00 00 00 C9 C3 90 90 90 90 90 90 FF 25 38 20 40 00 90 90 00 00 00 00 00 00 00 00 FF FF FF FF 00 00 00 00 FF FF FF FF 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Nullsoft_Install_System_v2_0a0
{
strings:
		$a0 = { 83 EC 0C 53 56 57 FF 15 B4 10 40 00 05 E8 03 00 00 BE E0 E3 41 00 89 44 24 10 B3 20 FF 15 28 10 40 00 68 00 04 00 00 FF 15 14 11 40 00 50 56 FF 15 10 11 40 00 80 3D E0 E3 41 00 22 75 08 80 C3 02 BE E1 E3 41 00 8A 06 8B 3D 14 12 40 00 84 C0 74 19 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00  }

condition:
		$a0 at entrypoint
}
	
	
rule DBPE_v1_53
{
strings:
		$a0 = { 9C 55 57 56 52 51 53 9C FA E8 ?? ?? ?? ?? 5D 81 ED 5B 53 40 ?? B0 ?? E8 ?? ?? ?? ?? 5E 83 C6 11 B9 27 ?? ?? ?? 30 06 46 49 75 FA  }

condition:
		$a0 at entrypoint
}
	
	
rule Lockless_Intro_Pack
{
strings:
		$a0 = { 2C E8 ?? ?? ?? ?? 5D 8B C5 81 ED F6 73 ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 06 89 85  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__ACProtect_1_09______Anorganix
{
strings:
		$a0 = { 60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE_v2_00b_rule__extra_
{
strings:
		$a0 = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 02 00 72 ?? B4 09 BA ?? ?? CD 21 B8 01 4C CD 21 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EA ?? ?? ?? ?? F3 A5 C3 59 2D ?? ?? 8E D0 51 2D ?? ?? 50 80  }

condition:
		$a0 at entrypoint
}
	
	
rule VBOX_v4_2_MTE
{
strings:
		$a0 = { 8C E0 0B C5 8C E0 0B C4 03 C5 74 00 74 00 8B C5  }

condition:
		$a0 at entrypoint
}
	
	
rule Shrinker_v3_2
{
strings:
		$a0 = { 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 65 68 00 01 ?? ?? E8 ?? E6 FF FF 83 C4 04 8B 75 08 A3 ?? ?? ?? ?? 85 F6 74 1D 68 FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Shrinker_v3_3
{
strings:
		$a0 = { 83 3D ?? ?? ?? 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule Shrinker_v3_4
{
strings:
		$a0 = { 83 3D B4 ?? ?? ?? ?? 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 ?? 0B 00 00 83 C4 04 8B 75 08 A3 B4 ?? ?? ?? 85 F6 74 23 83 7D 0C 03 77 1D 68 FF  }
	$a1 = { BB ?? ?? BA ?? ?? 81 C3 07 00 B8 40 B4 B1 04 D3 E8 03 C3 8C D9 49 8E C1 26 03 0E 03 00 2B  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PureBasic_4_x_DLL____Neil_Hodgson
{
strings:
		$a0 = { 83 7C 24 08 01 75 0E 8B 44 24 04 A3 ?? ?? ?? 10 E8 22 00 00 00 83 7C 24 08 02 75 00 83 7C 24 08 00 75 05 E8 ?? 00 00 00 83 7C 24 08 03 75 00 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? 0F 00 00 A3  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_PROTECT_0_9
{
strings:
		$a0 = { E9 CF 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Eddie_1028
{
strings:
		$a0 = { E8 ?? ?? 5E FC 83 ?? ?? 81 ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E B8 FE 4B CD 21 81 FF BB 55 ?? ?? 07 ?? ?? ?? 07 B4 49 CD 21 BB FF FF B4 48 CD 21  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_V5_20____Silicon_Realms_Toolworks_____Sign_By_fly___20080214
{
strings:
		$a0 = { E8 38 3D 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 98 1E 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 EC 1C 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 7D 1C 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? ?? 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 FE 1A 00 00 59 89 7D FC FF 75 08 E8 56 45 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 96 D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 C0 FA FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 A4 19 00 00 59 C3 3B DF 75 0D 8B 45 10 3B C7 74 06 C7 00 0C 00 00 00 8B C3 E8 CC 1D 00 00 C3 55 8B EC 51 83 65 FC 00 57 8D 45 FC 50 FF 75 0C FF 75 08 E8 CA FE FF FF 8B F8 83 C4 0C 85 FF 75 19 56 8B 75 FC 85 F6 74 10 E8 C9 1B 00 00 85 C0 74 07 E8 C0 1B 00 00 89 30 5E 8B C7 5F C9 C3 6A 0C 68 ?? ?? ?? ?? E8 3B 1D 00 00 8B 75 08 85 F6 74 75 83 3D ?? ?? ?? ?? ?? 75 43 6A 04 E8 FF 19 00 00 59 83 65 FC 00 56 E8 84 3C 00 00 59 89 45 E4 85 C0 74 09 56 50 E8 A0 3C 00 00 59 59 C7 45 FC FE FF FF FF E8 0B 00 00 00 83 7D E4 00 75 37 FF 75 08 EB 0A 6A 04 E8 ED 18 00 00 59 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule MicroJoiner_1_6____coban2k
{
strings:
		$a0 = { 33 C0 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_2_628____Jtit
{
strings:
		$a0 = { E8 00 00 00 00 58 BB 34 1D 00 00 2B C3 50 68 00 00 40 00 68 00 40 00 00 68 BC 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Borland_Delphi_5_0_KOL_MCK______Anorganix
{
strings:
		$a0 = { 55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90  }

condition:
		$a0 at entrypoint
}
	
	
rule PECompact_v1_66
{
strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 DA 90 40 ?? 01 85 DE 90 40 ?? 01 85 E2 90 40 ?? BB 5B 11  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Crypt_v1_00_v1_01
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_75a
{
strings:
		$a0 = { 55 8B EC 6A FF 68 68 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_PACK_v1_0_by_ANAKiN_1998______
{
strings:
		$a0 = { 74 ?? E9 ?? ?? ?? ?? 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PRO_PACK_v2_08
{
strings:
		$a0 = { 8C D3 8E C3 8C CA 8E DA 8B 0E ?? ?? 8B F1 83 ?? ?? 8B FE D1 ?? FD F3 A5 53  }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor_2_2_4____Strongbit_SoftComplete_Development__h1_
{
strings:
		$a0 = { E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 04 00 00 00 FF FF FF FF 5E C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Free_Pascal_v0_99_10
{
strings:
		$a0 = { E8 00 6E 00 00 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 29  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE_Shield_V0_1b_V0_8____SMoKE
{
strings:
		$a0 = { E8 04 00 00 00 83 ?? ?? ?? 5D EB 05 45 55 EB 04 ?? EB F9 ?? C3 E8 00 00 00 00 5D EB 01 ?? 81 ?? ?? ?? ?? ?? EB 02 ?? ?? 8D ?? ?? ?? ?? ?? EB 02 ?? ?? BA 9F 11 00 00 EB 01 ?? 8D ?? ?? ?? ?? ?? 8B 09 E8 14 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 58 40 50 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Hafen_1641
{
strings:
		$a0 = { E8 ?? ?? 01 ?? ?? ?? CE CC 25 ?? ?? 25 ?? ?? 25 ?? ?? 40 51 D4 ?? ?? ?? CC 47 CA ?? ?? 46 8A CC 44 88 CC  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_V3_X_V6_X____Silicon_Realms_Toolworks_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 60 33 C9 75 02 EB 15 EB 33  }

condition:
		$a0 at entrypoint
}
	
	
rule SDProtect____Randy_Li
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_v1_2_5_0____Obsidium_Software
{
strings:
		$a0 = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule SimplePack_1_11_Method_2_NT_____bagierule__TMX_
{
strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_Full_Edition_1_17_rule__aPLib_____Ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 74 1F 00 00 8D 9D 1E 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34  }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin_V1_304____cyberbob_____Sign_By_fly___20080310
{
strings:
		$a0 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 ?? DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? EB 01 ?? EB 0D ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 ?? EB FB ?? ?? ?? ?? ?? ?? ?? 8B 42 3C 03 C2 ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 ?? ?? ?? ?? EB 06 ?? ?? ?? ?? ?? ?? F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule WinZip__32_bit__6_x
{
strings:
		$a0 = { FF 15 FC 81 40 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_v0_89_6___v1_02___v1_05___v1_22_DLL
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_5_5____Obsidium_Software_____Sign_By_fly___20080411
{
strings:
		$a0 = { EB 01 ?? E8 2B 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 23 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 02 ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 ?? ?? ?? ?? EB 01 ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 01 ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule Guardant_Stealth_aka_Novex_Dongle
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 60 E8 51 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule DIET_v1_02b__v1_10a__v1_20
{
strings:
		$a0 = { BE ?? ?? BF ?? ?? B9 ?? ?? 3B FC 72 ?? B4 4C CD 21 FD F3 A5 FC  }

condition:
		$a0 at entrypoint
}
	
	
rule The_Guard_Library
{
strings:
		$a0 = { 50 E8 ?? ?? ?? ?? 58 25 ?? F0 FF FF 8B C8 83 C1 60 51 83 C0 40 83 EA 06 52 FF 20 9D C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Packanoid____Arkanoid
{
strings:
		$a0 = { BF 00 10 40 00 BE ?? ?? ?? 00 E8 9D 00 00 00 B8  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Armor_0_49____Hying
{
strings:
		$a0 = { 56 52 51 53 55 E8 15 01 00 00 32 ?? ?? 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Dev_C___v4_9_9
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 90 90 90 90 55 89 E5 5D E9 ?? ?? 00 00 90 90 90 90 90 90 90  }

condition:
		$a0 at entrypoint
}
	
	
rule NsPacK_V3_4_V3_5____LiuXingPing_____Sign_By_fly
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 01 0F 84  }

condition:
		$a0 at entrypoint
}
	
	
rule JDPack
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 81 EA 06 ?? ?? ?? 89 95 ?? ?? ?? ?? 83 BD 45  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE_Manager_Version_3_0_1994__c__Solar_Designer
{
strings:
		$a0 = { B4 30 1E 06 CD 21 2E ?? ?? ?? BF ?? ?? B9 ?? ?? 33 C0 2E ?? ?? 47 E2  }

condition:
		$a0 at entrypoint
}
	
	
rule DxPack_1_0
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84  }

condition:
		$a0 at entrypoint
}
	
	
rule TopSpeed_v3_01_1989
{
strings:
		$a0 = { 1E BA ?? ?? 8E DA 8B ?? ?? ?? 8B ?? ?? ?? FF ?? ?? ?? 50 53  }

condition:
		$a0 at entrypoint
}
	
	
rule ARC_SFX_Archive
{
strings:
		$a0 = { 8C C8 8C DB 8E D8 8E C0 89 ?? ?? ?? 2B C3 A3 ?? ?? 89 ?? ?? ?? BE ?? ?? B9 ?? ?? BF ?? ?? BA ?? ?? FC AC 32 C2 8A D8  }

condition:
		$a0 at entrypoint
}
	
	
rule diProtector_V1_X____diProtector_Software_____Sign_By_fly
{
strings:
		$a0 = { 01 00 A0 E3 14 00 00 EB 00 00 20 E0 44 10 9F E5 03 2A A0 E3 40 30 A0 E3 AE 00 00 EB 30 00 8F E5 00 20 A0 E1 3A 0E 8F E2 00 00 80 E2 1C 10 9F E5 20 30 8F E2 0E 00 00 EB 14 00 9F E5 14 10 9F E5 7F 20 A0 E3 C5 00 00 EB 04 C0 8F E2 00 F0 9C E5  }

condition:
		$a0 at entrypoint
}
	
	
rule E_Language____WuTao_____Sign_By_fly
{
strings:
		$a0 = { E8 06 00 00 00 50 E8 ?? 01 00 00 55 8B EC 81 C4 F0 FE FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_2_rule___BJFNT_1_1b______Anorganix
{
strings:
		$a0 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 90  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_v0_24___v0_28_Alpha____Dwing
{
strings:
		$a0 = { BE 88 01 40 00 AD ?? ?? 95 AD 91 F3 A5 AD  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_31__Eng_____dulek_xt
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB  }

condition:
		$a0 at entrypoint
}
	
	
rule MZ0oPE_1_0_6b____TaskFall
{
strings:
		$a0 = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 ?? ?? ?? ?? C3 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4C 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE32_1_1
{
strings:
		$a0 = { 50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20 31  }

condition:
		$a0 at entrypoint
}
	
	
rule Sentinel_SuperPro__Automatic_Protection__v6_4_1____Safenet
{
strings:
		$a0 = { A1 ?? ?? ?? ?? 55 8B ?? ?? ?? 85 C0 74 ?? 85 ED 75 ?? A1 ?? ?? ?? ?? 50 55 FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 55 51 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 15 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 6A 00 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 01 00 00 00 5D C2 0C 00  }

condition:
		$a0 at entrypoint
}
	
	
rule LameCrypt_v1_0
{
strings:
		$a0 = { 60 66 9C BB ?? ?? ?? ?? 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61  }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin_V1_32____cyberbob_____Sign_By_fly___20080310
{
strings:
		$a0 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 17 E6 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? EB 01 ?? EB 0D FF E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 00 EB FB FF E8 02 00 00 00 ?? ?? 5A 81 ?? ?? ?? ?? ?? 83 EA FE 89 95 A9 57 40 00 2B C0 2B C9 83 F1 06 09 85 CB 57 40 00 9C D3 2C 24 80 C1 FB 21 0C 24 50 52 B8 36 C7 09 FF 05 FE 37 F6 00 F7 64 24 08 8D 84 28 B1 35 40 00 89 44 24 08 5A 58 8D 64 24 04 FF 64 24 FC CD 20 BB 69 74 58 0B C1 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule HEALTH_v_5_1_by_Muslim_M_Polyak
{
strings:
		$a0 = { 1E E8 ?? ?? 2E 8C 06 ?? ?? 2E 89 3E ?? ?? 8B D7 B8 ?? ?? CD 21 8B D8 0E 1F E8 ?? ?? 06 57 A1 ?? ?? 26  }

condition:
		$a0 at entrypoint
}
	
	
rule Fish_Pe_Packer_V1_02____hellfish_____Sign_By_fly___20090120
{
strings:
		$a0 = { 60 E8 07 00 00 00 61 68 ?? ?? ?? ?? C3 5E 56 8B 56 02 ?? ?? ?? AD 01 D0 5B 36 89 43 02 66 3E C7 43 FA EB 05 53 AD 01 D0 89 C3 C7 43 FC 00 10 00 00 C7 43 F8 00 80 00 00 89 53 F4 AD 01 D0 89 43 F0 AD 01 D0 89 43 10 52 6A 04 FF 73 FC AD 50 6A 00 3E FF 53 08 89 C5 6A 04 FF 73 FC AD 50 6A 00 3E FF 53 08 89 C1 5A 83 EE 08 AD 50 55 AD AD 50 AD 01 D0 50 6A 02 6A 00 6A ?? 51 89 CF FF 53 10 83 C4 20 FF 73 F8 6A 00 57 FF 53 0C  }

condition:
		$a0 at entrypoint
}
	
	
rule AntiDote_V1_2_Demo____SIS_Team_____Sign_By_fly
{
strings:
		$a0 = { E8 F7 FE FF FF 05 CB 22 00 00 FF E0 E8 EB FE FF FF 05 BB 19 00 00 FF E0 E8 BD 00 00 00 08 B2 62 00 01 52 17 0C 0F 2C 2B 20 7F 52 79 01 30 07 17 29 4F 01 3C 30 2B 5A 3D C7 26 11 26 06 59 0E 78 2E 10 14 0B 13 1A 1A 3F 64 1D 71 33 57 21 09 24 8B 1B 09 37 08 61 0F 1D 1D 2A 01 87 35 4C 07 39 0B  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____Borland_Delphi___Borland_C___
{
strings:
		$a0 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80  }
	$a1 = { EB 01 2E EB 02 A5 55 BB 80 ?? ?? 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PeCompact_2_53_DLL__Slim_Loader______BitSum_Technologies
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 00 08 0C 00 48 E1 01 56 57 53 55 8B 5C 24 1C 85 DB 0F 84 AB 21 E8 BD 0E E6 60 0D 0B 6B 65 72 6E 6C 33 32  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_0_51____tE_
{
strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 00 00 59 EB 01 EB AC 54 E8 03 00 00 00 5C EB 08 8D 64 24 04 FF 64 24 FC 6A 05 D0 2C 24 72 01 E8 01 24 24 5C F7 DC EB 02 CD 20 8D 64 24 FE F7 DC EB 02 CD 20 FE C8 E8 00 00 00 00 32 C1 EB 02 82 0D AA EB 03 82 0D 58 EB 02 1D 7A 49 EB 05 E8 01 00 00 00 7F AE 14 7E A0 77 76 75 74  }

condition:
		$a0 at entrypoint
}
	
	
rule xPEP_0_3x____xIkUg
{
strings:
		$a0 = { 55 53 56 51 52 57 E8 16 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule ass___crypter____by_santasdad
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 53 ?? ?? ?? ?? 89 45 EC B8 98 40 00 10 E8 AC EA FF FF 33 C0 55 68 78 51 00 10 64 ?? ?? ?? ?? 20 6A 0A 68 88 51 00 10 A1 E0 97 00 10 50 E8 D8 EA FF FF 8B D8 53 A1 E0 97 00 10 50 E8 12 EB FF FF 8B F8 53 A1 E0 97 00 10 50 E8 DC EA FF FF 8B D8 53 E8 DC EA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 F0 97 00 10 E8 C9 E7 FF FF B8 F0 97 00 10 E8 B7 E7 FF FF 8B CF 8B D6 E8 EE EA FF FF 53 E8 98 EA FF FF 8D 4D EC BA 9C 51 00 10 A1 F0 97 00 10 E8 22 EB FF FF 8B 55 EC B8 F0 97 00 10 E8 89 E6 FF FF B8 F0 97 00 10 E8 7F E7 FF FF E8 6E EC FF FF 33 C0 5A 59 59 64 89 10 68 7F 51 00 10 8D 45 EC E8 11 E6 FF FF C3 E9 FF DF FF FF EB F0 5F 5E 5B E8 0D E5 FF FF 00 53 45 54 54 49 4E 47 53 00 00 00 00 FF FF FF FF 1C 00 00 00 45 4E 54 45 52 20 59 4F 55 52 20 4F 57 4E 20 50 41 53 53 57 4F 52 44 20 48 45 52 45  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Embedded_V2_717_V2_719____Jitit_____Sign_By_fly
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 C1 FE FF FF E9 97 FF FF FF CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00  }

condition:
		$a0 at entrypoint
}
	
	
rule EmbedPE_v1_24____cyclotron
{
strings:
		$a0 = { 83 EC 50 60 68 ?? ?? ?? ?? E8 CB FF 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PC_Shrinker_v0_45
{
strings:
		$a0 = { BD ?? ?? ?? ?? 01 AD E3 38 40 ?? FF B5 DF 38 40  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_10b2
{
strings:
		$a0 = { 55 8B EC 6A FF 68 18 12 41 00 68 24 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Simple_UPX_Cryptor_V30_4_2005____MANtiCORE
{
strings:
		$a0 = { 60 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? ?? ?? ?? ?? E2 FA 61 68 ?? ?? ?? ?? C3  }

condition:
		$a0 at entrypoint
}
	
	
rule MSLRH_v0_31a
{
strings:
		$a0 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 0F C0 C9 D2 D1 0F C1 C0 D3 DA C0 D6 A8 EB 01 DE D0 EC 0F C1 CB D0 CF 0F C1 D1 D2 DB 0F C8 EB 01 BC C0 E9 C6 C1 D0 91 0F CB EB 01 73 0F CA 87 D9 87 D2 D0 CF 87 D9 0F C8 EB 01 C1 EB 01 A2 86 CA D0 E1 0F C0 CB 0F CA C0 C7 91 0F CB C1 D9 0C 86 F9 86 D7 D1 D9 EB 01 A5 EB 01 11 EB 01 1D 0F C1 C2 0F CB 0F C1 C2 EB 01 A1 C0 E9 FD 0F C1 D1 EB 01 E3 0F CA 87 D9 EB 01 F3 0F CB 87 C2 0F C0 F9 D0 F7 EB 01 2F 0F C9 C0 DC C4 EB 01 35 0F CA D3 D1 86 C8 EB 01 01 0F C0 F5 87 C8 D0 DE EB 01 95 EB 01 E1 EB 01 FD EB 01 EC 87 D3 0F CB C1 DB 35 D3 E2 0F C8 86 E2 86 EC C1 FB 12 D2 EE 0F C9 D2 F6 0F CA 87 C3 C1 D3 B3 EB 01 BF D1 CB 87 C9 0F CA 0F C1 DB EB 01 44 C0 CA F2 0F C1 D1 0F CB EB 01 D3 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule VProtector_V1_0B____vcasm
{
strings:
		$a0 = { 55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50  }

condition:
		$a0 at entrypoint
}
	
	
rule NeoLite_v1_0
{
strings:
		$a0 = { 8B 44 24 04 8D 54 24 FC 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 FF 25  }

condition:
		$a0 at entrypoint
}
	
	
rule nPack_v1_1_150_200_Beta____NEOx
{
strings:
		$a0 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? 00 E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_HiT_v0_0_1
{
strings:
		$a0 = { 94 BC ?? ?? ?? 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C_v2_0
{
strings:
		$a0 = { 53 56 57 BB ?? ?? ?? ?? 8B ?? ?? ?? 55 3B FB 75  }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor_V2_1X____softcomplete_com
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? ?? ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1  }

condition:
		$a0 at entrypoint
}
	
	
rule RCryptor_V1_6d____Vaska_____Sign_By_fly
{
strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 90 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 B8 ?? ?? ?? ?? 90 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3  }

condition:
		$a0 at entrypoint
}
	
	
rule EXECryptor_2_2_6_DLL__minimum_protection_
{
strings:
		$a0 = { 50 8B C6 87 04 24 68 ?? ?? ?? ?? 5E E9 ?? ?? ?? ?? 85 C8 E9 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 0F 81 ?? ?? ?? 00 81 FA ?? ?? ?? ?? 33 D0 E9 ?? ?? ?? 00 0F 8D ?? ?? ?? 00 81 D5 ?? ?? ?? ?? F7 D1 0B 15 ?? ?? ?? ?? C1 C2 ?? 81 C2 ?? ?? ?? ?? 9D E9 ?? ?? ?? ?? C1 E2 ?? C1 E8 ?? 81 EA ?? ?? ?? ?? 13 DA 81 E9 ?? ?? ?? ?? 87 04 24 8B C8 E9 ?? ?? ?? ?? 55 8B EC 83 C4 F8 89 45 FC 8B 45 FC 89 45 F8 8B 45 08 E9 ?? ?? ?? ?? 8B 45 E0 C6 00 00 FF 45 E4 E9 ?? ?? ?? ?? FF 45 E4 E9 ?? ?? ?? 00 F7 D3 0F 81 ?? ?? ?? ?? E9 ?? ?? ?? ?? 87 34 24 5E 8B 45 F4 E8 ?? ?? ?? 00 8B 45 F4 8B E5 5D C3 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule yP_v1_0b_by_Ashkbiz_Danehkar
{
strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 C2 E8 03 00 00 00 EB 01 ?? AC ?? ?? ?? ?? ?? ?? ?? EB 01 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 01 E8 ?? AA E2 9C  }

condition:
		$a0 at entrypoint
}
	
	
rule DEF_v1_0
{
strings:
		$a0 = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? 10 40 00 C3  }
	$a1 = { BE ?? 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ZCode_Win32_PE_Protector_v1_01
{
strings:
		$a0 = { E9 12 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E9 FB FF FF FF C3 68 ?? ?? ?? ?? 64 FF 35  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Diminisher_v0_1
{
strings:
		$a0 = { 5D 8B D5 81 ED A2 30 40 ?? 2B 95 91 33 40 ?? 81 EA 0B ?? ?? ?? 89 95 9A 33 40 ?? 80 BD 99  }
	$a1 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74 50 E8 02 01 00 00 8B FD 8D 9D 9A 33 40 00 8B 1B 8D 87  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule ASProtect_v1_1_MTE
{
strings:
		$a0 = { 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule SmartE____Microsoft
{
strings:
		$a0 = { EB 15 03 00 00 00 ?? 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 8F 07 00 00 89 85 83 07 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 2F 06 00 00 E8 8E 04 00 00 49 0F 88 23 06  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_v0_99_Special_Build____heXer___forgot
{
strings:
		$a0 = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 ?? ?? 00 F5 ?? ?? 00 ED ?? ?? 00 00 00 00 00 00 00 00 00 12 ?? ?? 00 FD ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__August_16th__Iron_Maiden_
{
strings:
		$a0 = { BA 79 02 03 D7 B4 1A CD 21 B8 24 35 CD 21 5F 57 89 9D 4E 02 8C 85 50 02  }

condition:
		$a0 at entrypoint
}
	
	
rule Pohernah_1_0_1___by_Kas
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F1 26 40 00 8B BD 18 28 40 00 8B 8D 20 28 40 00 B8 38 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 1C 28 40 00 31 C0 51 31 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 1C 28 40 00 8B 85 24 28 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 89 CE E8 27 00 00 00 89 C1 5F B8 38 28 40 00 01 E8 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 14 28 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 21 FE 89 F0 5F 5E C3 60 83 F0 05 40 90 48 83 F0 05 89 C6 89 D7 60 E8 0B 00 00 00 61 83 C7 08 83 E9 07 E2 F1 61 C3 57 8B 1F 8B 4F 04 68 B9 79 37 9E 5A 42 89 D0 48 C1 E0 05 BF 20 00 00 00 4A 89 DD C1 E5 04 29 E9 8B 6E 08 31 DD 29 E9 89 DD C1 ED 05 31 C5 29 E9 2B 4E 0C 89 CD C1 E5 04 29 EB 8B 2E 31 CD 29 EB 89 CD C1 ED 05 31 C5 29 EB 2B 5E 04 29 D0 4F 75 C8 5F 89 1F 89 4F 04 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoiner_Small__build_035_____GlOFF
{
strings:
		$a0 = { 51 33 CB 86 C9 59 E8 9E FD FF FF 66 87 DB 6A 00 E8 0C 00 00 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_Neolite_2_0_____emadicius
{
strings:
		$a0 = { E9 A6 00 00 00 B0 7B 40 00 78 60 40 00 7C 60 40 00 00 00 00 00 B0 3F 00 00 12 62 40 00 4E 65 6F 4C 69 74 65 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 43 6F 6D 70 72 65 73 73 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 38 2C 31 39 39 39 20 4E 65 6F 57 6F 72 78 20 49 6E 63 0D 0A 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 37 2D 31 39 39 39 20 4C 65 65 20 48 61 73 69 75 6B 0D 0A 41 6C 6C 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 2E 00 00 00 00 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule mucki_s_protector_I____mucki
{
strings:
		$a0 = { BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 F7 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Mew_5_0_1____NorthFox___HCC
{
strings:
		$a0 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA E2 F4 C3 00 ?? ?? 00 ?? ?? ?? 00 00 10 40 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__32Lite_0_03______Anorganix
{
strings:
		$a0 = { 60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 ?? ?? ?? ?? E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_6_0____Obsidium_Software_____Sign_By_fly___20080730
{
strings:
		$a0 = { EB 02 ?? ?? 50 EB 01 ?? E8 ?? 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 1F EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 33 C0 EB 01 ?? 64 FF 30 EB 04 ?? ?? ?? ?? 64 89 20 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 ?? 00 00 00 EB 01 ?? E8 ?? FF FF FF EB 01 ?? EB 03 ?? ?? ?? EB 02 ?? ?? EB 02 ?? ?? 64 8F 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule RJoiner_1_2_by_Vaska__25_03_2007_16_58_
{
strings:
		$a0 = { 55 8B EC 81 EC 0C 02 00 00 8D 85 F4 FD FF FF 56 50 68 04 01 00 00 FF 15 14 10 40 00 90 8D 85 F4 FD FF FF 50 FF 15 10 10 40 00 90 BE 00 20 40 00 90 83 3E FF 0F 84 84 00 00 00 53 57 33 FF 8D 46  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____Borland_Delphi_2_0_
{
strings:
		$a0 = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB  }

condition:
		$a0 at entrypoint
}
	
	
rule yzpack_V2_0____UsAr_____Sign_By_fly
{
strings:
		$a0 = { 25 ?? ?? ?? ?? 61 87 CC 55 45 45 55 81 ED CA 00 00 00 55 A4 B3 02 FF 14 24 73 F8 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 1F B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3C AA EB DC FF 54 24 04 2B CB 75 0F FF 54 24 08 EB 27 AC D1 E8 74 30 13 C9 EB 1B 91 48 C1 E0 08 AC FF 54 24 08 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 99 BD ?? ?? ?? ?? FF 65 28  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__PEX_0_99______Anorganix
{
strings:
		$a0 = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Gardian_Angel_1_0
{
strings:
		$a0 = { 06 8C C8 8E D8 8E C0 FC BF ?? ?? EB  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_ASProtect_1_0_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 01 00 00 00 90 5D 81 ED 00 00 00 00 BB 00 00 00 00 03 DD 2B 9D  }

condition:
		$a0 at entrypoint
}
	
	
rule Wise_Installer_Stub
{
strings:
		$a0 = { 55 8B EC 81 EC ?? 04 00 00 53 56 57 6A ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? 40 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 ?? 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 74  }
	$a1 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 00 8B 3D 2C 20 40 00 53 53 6A 03 53 6A 01 8D 85 94 FD FF FF 68 00 00 00 80 50 FF D7 83 F8 FF 89 45 FC 0F 84 7B 01 00 00 8D 85 90 FC FF FF 50 56 FF 15 28 20 40 00 8D 85 98 FE FF FF 50 53 8D 85 90 FC FF FF 68 10 30 40 00 50 FF 15 24 20 40 00 53 68 80 00 00 00 6A 02 53 53 8D 85 98 FE FF FF 68 00 00 00 40 50 FF D7 83 F8 FF 89 45 F4 0F 84 2F 01 00 00 53 53 53 6A 02 53 FF 75 FC FF 15 00 20 40 00 53 53 53 6A 04 50 89 45 F8 FF 15 1C 20 40 00 8B F8 C7 45 FC 01 00 00 00 8D 47 01 8B 08 81 F9 4D 5A 9A 00 74 08 81 F9 4D 5A 90 00 75 06 80 78 04 03 74 0D FF 45 FC 40 81 7D FC 00 80 00 00 7C DB 8D 4D F0 53 51 68  }
	$a2 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 ?? 40 40 00 FF 15 ?? 40 40 00 8B F8 89 7D ?? 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D ?? 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D ?? EB EF 80 3F 22 75 04 47 89 7D ?? 80 3F 20 75 09 47 80 3F 20 74 FA 89 7D ?? 53 FF 15 ?? 40 40 00 80 3F 2F 89 45 ?? 75 ?? 8A 47 01 3C 53 74 04 3C 73 75 06 89 35  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule SecureEXE_3_0____ZipWorx
{
strings:
		$a0 = { E9 B8 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Number_One
{
strings:
		$a0 = { F9 07 3C 53 6D 69 6C 65 3E E8  }

condition:
		$a0 at entrypoint
}
	
	
rule Wind_of_Crypt_1_0___by_DarkPressure
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 53 ?? ?? ?? ?? 89 45 EC B8 64 40 00 10 E8 28 EA FF FF 33 C0 55 68 CE 51 00 10 64 ?? ?? ?? ?? 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 F6 DB FF FF 8B 45 EC E8 12 E7 FF FF 50 E8 3C EA FF FF 8B D8 83 FB FF 0F 84 A6 00 00 00 6A 00 53 E8 41 EA FF FF 8B F0 81 EE 00 5E 00 00 6A 00 6A 00 68 00 5E 00 00 53 E8 52 EA FF FF B8 F4 97 00 10 8B D6 E8 2E E7 FF FF B8 F8 97 00 10 8B D6 E8 22 E7 FF FF 8B C6 E8 AB D8 FF FF 8B F8 6A 00 68 F0 97 00 10 56 A1 F4 97 00 10 50 53 E8 05 EA FF FF 53 E8 CF E9 FF FF B8 FC 97 00 10 BA E8 51 00 10 E8 74 EA FF FF A1 F4 97 00 10 85 C0 74 05 83 E8 04 8B 00 50 B9 F8 97 00 10 B8 FC 97 00 10 8B 15 F4 97 00 10 E8 D8 EA FF FF B8 FC 97 00 10 E8 5A EB FF FF 8B CE 8B 15 F8 97 00 10 8B C7 E8 EB E9 FF FF 8B C7 85 C0 74 05 E8 E4 EB FF FF 33 C0 5A 59 59 64 89 10 68 D5 51 00 10 8D 45 EC E8 BB E5 FF FF C3 E9 A9 DF FF FF EB F0 5F 5E 5B E8 B7 E4 FF FF 00 00 00 FF FF FF FF 0A 00 00 00 63 5A 6C 56 30 55 6C 6B 70 4D  }

condition:
		$a0 at entrypoint
}
	
	
rule AINEXE_v2_1
{
strings:
		$a0 = { A1 ?? ?? 2D ?? ?? 8E D0 BC ?? ?? 8C D8 36 A3 ?? ?? 05 ?? ?? 36 A3 ?? ?? 2E A1 ?? ?? 8A D4 B1 04 D2 EA FE C9  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE_joiner____Amok
{
strings:
		$a0 = { A1 14 A1 40 00 C1 E0 02 A3 18 A1 40  }

condition:
		$a0 at entrypoint
}
	
	
rule Reg2Exe_2_20_2_21___by_Jan_Vorel
{
strings:
		$a0 = { 6A 00 E8 7D 12 00 00 A3 A0 44 40 00 E8 79 12 00 00 6A 0A 50 6A 00 FF 35 A0 44 40 00 E8 0F 00 00 00 50 E8 69 12 00 00 CC CC CC CC CC CC CC CC CC 68 2C 02 00 00 68 00 00 00 00 68 B0 44 40 00 E8 3A 12 00 00 83 C4 0C 8B 44 24 04 A3 B8 44 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 32 12 00 00 A3 B0 44 40 00 68 F4 01 00 00 68 BC 44 40 00 FF 35 B8 44 40 00 E8 1E 12 00 00 B8 BC 44 40 00 89 C1 8A 30 40 80 FE 5C 75 02 89 C1 80 FE 00 75 F1 C6 01 00 E8 EC 18 00 00 E8 28 16 00 00 E8 4A 12 00 00 68 00 FA 00 00 68 08 00 00 00 FF 35 B0 44 40 00 E8 E7 11 00 00 A3 B4 44 40 00 8B 15 D4 46 40 00 E8 65 0A 00 00 BB 00 00 10 00 B8 01 00 00 00 E8 72 0A 00 00 74 09 C7 00 01 00 00 00 83 C0 04 A3 D4 46 40 00 FF 35 B4 44 40 00 E8 26 05 00 00 8D 0D B8 46 40 00 5A E8 CF 0F 00 00 FF 35 B4 44 40 00 FF 35 B8 46 40 00 E8 EE 06 00 00 8D 0D B4 46 40 00 5A E8  }

condition:
		$a0 at entrypoint
}
	
	
rule AverCryptor_1_02_beta____os1r1s
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0C 17 40 00 8B BD 33 18 40 00 8B 8D 3B 18 40 00 B8 51 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 37 18 40 00 33 C0 51 33 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 37 18 40 00 8B 85 3F 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 51 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 2F 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_Full_Edition_1_17_DLL_rule__LZMA_____Ap0x
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 EB 09 00 00 89 85  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_20
{
strings:
		$a0 = { 55 8B EC 6A FF 68 10 12 41 00 68 F4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Gotcha_879
{
strings:
		$a0 = { E8 ?? ?? 5B 81 EB ?? ?? 9C FC 2E ?? ?? ?? ?? ?? ?? ?? 8C D8 05 ?? ?? 2E ?? ?? ?? ?? 50 2E ?? ?? ?? ?? ?? ?? 8B C3 05 ?? ?? 8B F0 BF 00 01 B9 20 00 F3 A4 0E B8 00 01 50 B8 DA DA CD 21  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE_v1_50__Device_driver_compression_
{
strings:
		$a0 = { B4 09 BA 14 01 CD 21 B8 00 4C CD 21 F8 9C 50 53 51 52 56 57 55 1E 06 BB  }

condition:
		$a0 at entrypoint
}
	
	
rule Cygwin32
{
strings:
		$a0 = { 55 89 E5 83 EC 04 83 3D  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH_
{
strings:
		$a0 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_PEtite_2_2_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 B8 00 00 00 00 68 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50  }

condition:
		$a0 at entrypoint
}
	
	
rule EncryptPE_V2_20090726____WFS_____Sign_By_fly___20090822
{
strings:
		$a0 = { 6A ?? 60 E9 01 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 61 58 8B 44 24 F8 E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_v0_33___v0_34_Beta____Dwing
{
strings:
		$a0 = { 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40  }

condition:
		$a0 at entrypoint
}
	
	
rule IProtect_1_0__FxSub_dll_mode____by_FuXdas
{
strings:
		$a0 = { EB 33 2E 46 55 58 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 46 78 53 75 62 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 60 E8 00 00 00 00 5D 81 ED B6 13 40 00 FF 74 24 20 E8 40 00 00 00 0B C0 74 2F 89 85 A8 13 40 00 8D 85 81 13 40 00 50 FF B5 A8 13 40 00 E8 92 00 00 00 0B C0 74 13 89 85 A4 13 40 00 8D 85 8E 13 40 00 50 FF 95 A4 13 40 00 8B 85 AC 13 40 00 89 44 24 1C 61 FF E0 8B 7C 24 04 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 98 13 40 00 89 20 89 68 04 8D 9D 4F 14 40 00 89 58 08 64 89 25 00 00 00 00 81 E7 00 00 FF FF 66 81 3F 4D 5A 75 0F 8B F7 03 76 3C 81 3E 50 45 00 00 75 02 EB 17 81 EF 00 00 01 00 81 FF 00 00 00 70 73 07 BF 00 00 F7 BF EB 02 EB D3 97 64 8F 05 00 00 00 00 83 C4 04 C2 04 00 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 98 13 40 00 89 20 89 68 04 8D 9D 4F 14 40 00 89 58 08 64 89 25 00 00 00 00 8B 74 24 0C 66 81 3E 4D 5A 74 05 E9 8A 00 00 00 03 76 3C 81 3E 50 45 00 00 74 02 EB 7D 8B 7C 24 10 B9 96 00 00 00 32 C0 F2 AE 8B CF 2B 4C 24 10 8B 56 78 03 54 24 0C 8B 5A 20 03 5C 24 0C 33 C0 8B 3B 03 7C 24 0C 8B 74 24 10 51 F3 A6 75 05 83 C4 04 EB 0A 59 83 C3 04 40 3B 42 18 75 E2 3B 42 18 75 02 EB 35 8B 72 24 03 74 24 0C 52 BB 02 00 00 00 33 D2 F7 E3 5A 03 C6 33 C9 66 8B 08 8B 7A 1C 33 D2 BB 04 00 00 00 8B C1 F7 E3 03 44 24 0C 03 C7 8B 00 03 44 24 0C EB 02 33 C0 64 8F 05 00 00 00 00 83 C4 04 C2 08 00 E8 B5 FA FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule PEBundle_v0_2___v2_0x
{
strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95  }

condition:
		$a0 at entrypoint
}
	
	
rule Fish_PE_Shield_1_01____HellFish
{
strings:
		$a0 = { 60 E8 12 FE FF FF C3 90 09 00 00 00 2C 00 00 00 ?? ?? ?? ?? C4 03 00 00 BC A0 00 00 00 40 01 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 00 00 00 00 8A 00 00 00 10 00 00 28 88 00 00 40 ?? 4B 00 00 00 02 00 00 00 A0 00 00 18 01 00 00 40 ?? 4C 00 00 00 0C 00 00 00 B0 00 00 38 0A 00 00 40 ?? 4E 00 00 00 00 00 00 00 C0 00 00 40 39 00 00 40 ?? 4E 00 00 00 08 00 00 00 00 01 00 C8 06 00 00 40  }

condition:
		$a0 at entrypoint
}
	
	
rule DCrypt_Private_0_9b____drmist
{
strings:
		$a0 = { B9 ?? ?? ?? 00 E8 00 00 00 00 58 68 ?? ?? ?? 00 83 E8 0B 0F 18 00 D0 00 48 E2 FB C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_0_24___0_27_beta___0_28_alpha____Dwing
{
strings:
		$a0 = { BE 88 01 40 00 AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0  }

condition:
		$a0 at entrypoint
}
	
	
rule Eagle_Protector_V2_2____AntiDebugLIB_____Sign_By_fly___20081008
{
strings:
		$a0 = { E8 ?? ?? ?? ?? EB 01 ?? BB 55 ?? ?? ?? E8 ?? ?? ?? ?? EB 01 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 01 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 01 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 01 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 01 ?? 83 FB 55 E8 ?? ?? ?? ?? EB 01 ?? 75 2E E8 ?? ?? ?? ?? EB 01 ?? C3 60 E8 ?? ?? ?? 00 5D 81 ED ?? ?? ?? ?? 8B D5 81 C2 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? C3 C3 E8 ?? ?? ?? ?? EB 01 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 E8 ?? ?? ?? ?? EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE32Pack_v1_37
{
strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED 4C 8E 40  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v4_10____Silicon_Realms_Toolworks
{
strings:
		$a0 = { 55 8B EC 6A FF 68 F8 8E 4C 00 68 D0 EA 49 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4C 00 33 D2 8A D4 89 15 7C A5 4C 00 8B C8 81 E1 FF 00 00 00 89 0D 78 A5 4C 00 C1 E1 08 03 CA 89 0D 74 A5 4C 00 C1 E8 10 A3 70 A5  }

condition:
		$a0 at entrypoint
}
	
	
rule JDPack_2_x____JDPack
{
strings:
		$a0 = { 55 8B EC 6A FF 68 68 51 40 00 68 04 25 40 00 64 A1 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule bambam_V0_01____bedrock_____Sign_By_fly
{
strings:
		$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 ?? ?? ?? ?? E8 6C FD FF FF B9 05 00 00 00 8B F3 BF ?? ?? ?? ?? 53 F3 A5 E8 8D 05 00 00 8B 3D ?? ?? ?? ?? A1 ?? ?? ?? ?? 66 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B CF 89 45 E8 89 0D ?? ?? ?? ?? 66 89 55 EC 8B 41 3C 33 D2 03 C1 83 C4 10 66 8B 48 06 66 8B 50 14 81 E1 FF FF 00 00 8D 5C 02 18 8D 41 FF 85 C0  }

condition:
		$a0 at entrypoint
}
	
	
rule WARNING____TROJAN____RobinPE
{
strings:
		$a0 = { 60 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Haryanto
{
strings:
		$a0 = { 81 EB 2A 01 8B 0F 1E 5B 03 CB 0E 51 B9 10 01 51 CB  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Ncu_Li_1688
{
strings:
		$a0 = { 0E 1E B8 55 AA CD 21 3D 49 4C 74 ?? 0E 0E 1F 07 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_65b1
{
strings:
		$a0 = { 55 8B EC 6A FF 68 38 ?? ?? ?? 68 40 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 F4  }

condition:
		$a0 at entrypoint
}
	
	
rule Cruncher_v1_0
{
strings:
		$a0 = { 2E ?? ?? ?? ?? 2E ?? ?? ?? B4 30 CD 21 3C 03 73 ?? BB ?? ?? 8E DB 8D ?? ?? ?? B4 09 CD 21 06 33 C0 50 CB  }

condition:
		$a0 at entrypoint
}
	
	
rule AntiVirus_Vaccine_v_1_03
{
strings:
		$a0 = { FA 33 DB B9 ?? ?? 0E 1F 33 F6 FC AD 35 ?? ?? 03 D8 E2  }

condition:
		$a0 at entrypoint
}
	
	
rule VIRUS___I_Worm_Bagle
{
strings:
		$a0 = { 6A 00 E8 95 01 00 00 E8 9F E6 FF FF 83 3D 03 50 40 00 00 75 14 68 C8 AF 00 00 E8 01 E1 FF FF 05 88 13 00 00 A3 03 50 40 00 68 5C 57 40 00 68 F6 30 40 00 FF 35 03 50 40 00 E8 B0 EA FF FF E8 3A FC FF FF 83 3D 54 57 40 00 00 74 05 E8 F3 FA FF FF 68 E8 03 00 00 E8 B1 00 00 00 EB F4 CC FF 25 A4 40 40 00 FF 25 B8 40 40 00 FF 25 B4 40 40 00 FF 25 B0 40 40 00 FF 25 AC 40 40 00 FF 25 9C 40 40 00 FF 25 A0 40 40 00 FF 25 A8 40 40 00 FF 25 24 40 40 00 FF 25 28 40 40 00 FF 25 2C 40 40 00 FF 25 30 40 40 00 FF 25 34 40 40 00 FF 25 38 40 40 00 FF 25 3C 40 40 00 FF 25 40 40 40 00 FF 25 44 40 40 00 FF 25 48 40 40 00 FF 25 4C 40 40 00 FF 25 50 40 40 00 FF 25 54 40 40 00 FF 25 58 40 40 00 FF 25 5C 40 40 00 FF 25 60 40 40 00 FF 25 BC 40 40 00 FF 25 64 40 40 00 FF 25 68 40 40  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Embedded_V2_0X____Jitit_____Sign_By_fly
{
strings:
		$a0 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_3_8____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 ?? EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 01 ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 57 27 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_4_0_0_Beta____Obsidium_Software_____Sign_By_fly___20080102
{
strings:
		$a0 = { EB 01 ?? E8 2F 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 01 ?? E9 ?? ?? ?? ?? EB 01 ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule Minke_1_0_1___by_Codius
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 ?? ?? ?? ?? ?? 10 E8 7A F6 FF FF BE 68 66 00 10 33 C0 55 68 DB 40 00 10 64 FF 30 64 89 20 E8 FA F8 FF FF BA EC 40 00 10 8B C6 E8 F2 FA FF FF 8B D8 B8 6C 66 00 10 8B 16 E8 88 F2 FF FF B8 6C 66 00 10 E8 76 F2 FF FF 8B D0 8B C3 8B 0E E8 E3 E4 FF FF E8 2A F9 FF FF E8 C1 F8 FF FF B8 6C 66 00 10 8B 16 E8 6D FA FF FF E8 14 F9 FF FF E8 AB F8 FF FF 8B 06 E8 B8 E3 FF FF 8B D8 B8 6C 66 00 10 E8 38 F2 FF FF 8B D3 8B 0E E8 A7 E4 FF ?? ?? ?? ?? C4 FB FF FF E8 E7 F8 FF FF 8B C3 E8 B0 E3 FF FF E8 DB F8 FF FF 33 C0 5A 59 59 64 89 10 68 E2 40 00 10 C3 E9 50 EB FF FF EB F8 5E 5B E8 BB EF FF FF 00 00 00 43 41 31 38  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE_Stealth_v2_74____WebToolMaster
{
strings:
		$a0 = { EB 00 EB 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 90 E8 00 00 00 00 5D  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Borland_Delphi_6_0___7_0______Anorganix
{
strings:
		$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 53 8B D8 33 C0 A3 09 09 09 00 6A 00 E8 09 09 00 FF A3 09 09 09 00 A1 09 09 09 00 A3 09 09 09 00 33 C0 A3 09 09 09 00 33 C0 A3 09 09 09 00 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule NsPack_2_9____North_Star
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8A 06 3C 00 74 12 8B F5 8D B5 ?? ?? FF FF 8A 06 3C 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36  }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACK_v3_05c4__Unextractable___Virus_Shield_
{
strings:
		$a0 = { 03 05 40 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3  }

condition:
		$a0 at entrypoint
}
	
	
rule NsPacK_V3_0____LiuXingPing_____Sign_By_fly
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? ?? ?? 66 8B 06 66 83 F8 00 74  }

condition:
		$a0 at entrypoint
}
	
	
rule Unknown_by_SMT
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 83 ?? ?? 57 EB  }

condition:
		$a0 at entrypoint
}
	
	
rule PKZIP_SFX_v1_1_1989_90
{
strings:
		$a0 = { FC 2E 8C 0E ?? ?? A1 ?? ?? 8C CB 81 C3 ?? ?? 3B C3 72 ?? 2D ?? ?? 2D ?? ?? FA BC ?? ?? 8E D0 FB  }

condition:
		$a0 at entrypoint
}
	
	
rule PolyCryptor_by_SMT_Version__v3__v4
{
strings:
		$a0 = { EB ?? 28 50 6F 6C 79 53 63 72 79 70 74 20 ?? ?? ?? 20 62 79 20 53 4D 54 29  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Microsoft_Visual_C___6_0__Debug_Version_______Anorganix
{
strings:
		$a0 = { 55 8B EC 51 90 90 90 01 01 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_0_10___0_12_beta____Dwing
{
strings:
		$a0 = { BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1  }

condition:
		$a0 at entrypoint
}
	
	
rule pscrambler_1_2____by_p0ke
{
strings:
		$a0 = { 55 8B EC B9 04 00 00 00 6A 00 6A 00 49 75 F9 51 53 ?? ?? ?? ?? 10 E8 2D F3 FF FF 33 C0 55 68 E8 31 00 10 64 FF 30 64 89 20 8D 45 E0 E8 53 F5 FF FF 8B 45 E0 8D 55 E4 E8 30 F6 FF FF 8B 45 E4 8D 55 E8 E8 A9 F4 FF FF 8B 45 E8 8D 55 EC E8 EE F7 FF FF 8B 55 EC B8 C4 54 00 10 E8 D9 EC FF FF 83 3D C4 54 00 10 00 0F 84 05 01 00 00 80 3D A0 40 00 10 00 74 41 A1 C4 54 00 10 E8 D9 ED FF FF E8 48 E0 FF FF 8B D8 A1 C4 54 00 10 E8 C8 ED FF FF 50 B8 C4 54 00 10 E8 65 EF FF FF 8B D3 59 E8 69 E1 FF FF 8B C3 E8 12 FA FF FF 8B C3 E8 33 E0 FF FF E9 AD 00 00 00 B8 05 01 00 00 E8 0C E0 FF FF 8B D8 53 68 05 01 00 00 E8 57 F3 FF FF 8D 45 DC 8B D3 E8 39 ED FF FF 8B 55 DC B8 14 56 00 10 B9 00 32 00 10 E8 BB ED FF FF 8B 15 14 56 00 10 B8 C8 54 00 10 E8 53 E5 FF FF BA 01 00 00 00 B8 C8 54 00 10 E8 8C E8 FF FF E8 DF E0 FF FF 85 C0 75 52 6A 00 A1 C4 54 00 10 E8 3B ED FF FF 50 B8 C4 54 00 10 E8 D8 EE FF FF 8B D0 B8 C8 54 00 10 59 E8 3B E6 FF FF E8 76 E0 FF FF B8 C8 54 00 10 E8 4C E6 FF FF E8 67 E0 FF FF 6A 00 6A 00 6A 00 A1 14 56 00 10 E8 53 EE FF FF 50 6A 00 6A 00 E8 41 F3 FF FF 80 3D 9C 40 00 10 00 74 05 E8 EF FB FF FF 33 C0 5A 59 59 64 89 10 68 EF 31 00 10 8D 45 DC BA 05 00 00 00 E8 7D EB FF FF C3 E9 23 E9 FF FF EB EB 5B E8 63 EA FF FF 00 00 00 FF FF FF FF 08 00 00 00 74 65 6D 70 2E 65 78 65  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_Xtreme_Protector_1_05_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 E8 00 00 00 00 5D 81 00 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_ASPack_2_11d_____emadicius
{
strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule PESHiELD_v0_251
{
strings:
		$a0 = { 5D 83 ED 06 EB 02 EA 04 8D  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_v0_2_Beta____Dwing
{
strings:
		$a0 = { BE 88 01 ?? ?? AD 8B F8 95 A5 33 C0 33  }

condition:
		$a0 at entrypoint
}
	
	
rule Macromedia_Windows_Flash_Projector_Player_v5_0
{
strings:
		$a0 = { 83 EC 44 56 FF 15 70 61 44 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C 3C 20 7E 08 8A 46 01 46 3C 20 7F F8 8A 06 84 C0 74 0C 3C 20 7F 08 8A 46 01 46 84 C0 75 F4 8D 44 24 04 C7 44 24 30 00 00 00 00 50 FF 15 80 61 44 00 F6 44 24 30 01 74 0B 8B 44 24 34 25 FF FF 00 00 EB 05 B8 0A 00 00 00 50 56 6A 00 6A 00 FF 15 74 61 44 00 50 E8 18 00 00 00 50 FF 15 78 61 44 00 5E 83 C4 44 C3 90 90 90 90 90 90  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_6_1____Obsidium_Software_____Sign_By_fly___20080521
{
strings:
		$a0 = { EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? E8 ?? 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 ?? EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? 64 FF 30 EB 04 ?? ?? ?? ?? 64 89 20 EB 01 ?? EB 03 ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 01 ?? E8 ?? FF FF FF EB 01 ?? EB 03 ?? ?? ?? EB 01 ?? EB 03 ?? ?? ?? 64 8F 00 EB 03 ?? ?? ?? 83 C4 04 EB 01 ?? 58 EB 02 ?? ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_Microsoft_Visual_C_______emadicius
{
strings:
		$a0 = { 55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 64 8F 05 00 00 00 00 83 C4 0C 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACK_v3_05c4__Extr__Passw_check__Vir__shield_
{
strings:
		$a0 = { 03 05 C0 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3  }

condition:
		$a0 at entrypoint
}
	
	
rule Gamehouse_Media_Protector_Version_Unknown
{
strings:
		$a0 = { 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule KByS_V0_28____shoooo_____Sign_By_fly
{
strings:
		$a0 = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4  }

condition:
		$a0 at entrypoint
}
	
	
rule Fish_Pe_Packer_V1_03_V1_0X____hellfish_____Sign_By_fly___20090119
{
strings:
		$a0 = { 60 E8 21 00 00 00 EB 18 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5E 56 8B 56 1C 89 F3  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__VOB_ProtectCD_5______Anorganix
{
strings:
		$a0 = { 36 3E 26 8A C0 60 E8 00 00 00 00 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_Full_Edition_1_17_rule__LZMA_____Ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 73 26 00 00 8D 9D 58 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Microsoft_Visual_Basic_5_0___6_0______Anorganix
{
strings:
		$a0 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Eddie_1530
{
strings:
		$a0 = { E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? 50 06 56 1E 33 C0 50 1F C4 ?? ?? ?? 2E ?? ?? ?? ?? 2E  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_1_3_0_21____Obsidium_Software
{
strings:
		$a0 = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 26 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__FaxFree_Topo
{
strings:
		$a0 = { FA 06 33 C0 8E C0 B8 ?? ?? 26 ?? ?? ?? ?? 50 8C C8 26 ?? ?? ?? ?? 50 CC 58 9D 58 26 ?? ?? ?? ?? 58 26 ?? ?? ?? ?? 07 FB  }

condition:
		$a0 at entrypoint
}
	
	
rule SEN_Debug_Protector___
{
strings:
		$a0 = { BB ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 29 ?? ?? 4E E8  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_5_0_Dll____Silicon_Realms_Toolworks
{
strings:
		$a0 = { 83 7C 24 08 01 75 05 E8 DE 4B 00 00 FF 74 24 04 8B 4C 24 10 8B 54 24 0C E8 ED FE FF FF 59 C2 0C 00 6A 0C 68 ?? ?? ?? ?? E8 E5 24 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 8F 15 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 20 15 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 D7 23 00 00 59 89 7D FC FF 75 08 E8 EC 53 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 2B C5 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 19 ED FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 7D 22 00 00 59 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Pelles_C_2_90__3_00__4_00_DLL__X86_CRT_LIB_
{
strings:
		$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 BF 01 00 00 00 85 DB 75 10 83 3D ?? ?? ?? ?? 00 75 07 31 C0 E9 ?? ?? ?? ?? 83 FB 01 74 05 83 FB 02 75 ?? 85 FF 74  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Lockless_Intro_Pack______Anorganix
{
strings:
		$a0 = { 2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Macromedia_Windows_Flash_Projector_Player_v6_0
{
strings:
		$a0 = { 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C  }

condition:
		$a0 at entrypoint
}
	
	
rule IProtect_1_0__Fxlib_dll_mode____by_FuXdas
{
strings:
		$a0 = { EB 33 2E 46 55 58 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 46 78 4C 69 62 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 60 E8 00 00 00 00 5D 81 ED 71 10 40 00 FF 74 24 20 E8 40 00 00 00 0B C0 74 2F 89 85 63 10 40 00 8D 85 3C 10 40 00 50 FF B5 63 10 40 00 E8 92 00 00 00 0B C0 74 13 89 85 5F 10 40 00 8D 85 49 10 40 00 50 FF 95 5F 10 40 00 8B 85 67 10 40 00 89 44 24 1C 61 FF E0 8B 7C 24 04 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 53 10 40 00 89 20 89 68 04 8D 9D 0A 11 40 00 89 58 08 64 89 25 00 00 00 00 81 E7 00 00 FF FF 66 81 3F 4D 5A 75 0F 8B F7 03 76 3C 81 3E 50 45 00 00 75 02 EB 17 81 EF 00 00 01 00 81 FF 00 00 00 70 73 07 BF 00 00 F7 BF EB 02 EB D3 97 64 8F 05 00 00 00 00 83 C4 04 C2 04 00 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 53 10 40 00 89 20 89 68 04 8D 9D 0A 11 40 00 89 58 08 64 89 25 00 00 00 00 8B 74 24 0C 66 81 3E 4D 5A 74 05 E9 8A 00 00 00 03 76 3C 81 3E 50 45 00 00 74 02 EB 7D 8B 7C 24 10 B9 96 00 00 00 32 C0 F2 AE 8B CF 2B 4C 24 10 8B 56 78 03 54 24 0C 8B 5A 20 03 5C 24 0C 33 C0 8B 3B 03 7C 24 0C 8B 74 24 10 51 F3 A6 75 05 83 C4 04 EB 0A 59 83 C3 04 40 3B 42 18 75 E2 3B 42 18 75 02 EB 35 8B 72 24 03 74 24 0C 52 BB 02 00 00 00 33 D2 F7 E3 5A 03 C6 33 C9 66 8B 08 8B 7A 1C 33 D2 BB 04 00 00 00 8B C1 F7 E3 03 44 24 0C 03 C7 8B 00 03 44 24 0C EB 02 33 C0 64 8F 05 00 00 00 00 83 C4 04 C2 08 00 E8 FA FD FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_60c
{
strings:
		$a0 = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 F4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 F4  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_60a
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 94 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 B4  }

condition:
		$a0 at entrypoint
}
	
	
rule SkD_Undetectabler_Pro_2_0__No_UPX_Method_____SkD
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 FC 26 00 10 E8 EC F3 FF FF 6A 0F E8 15 F5 FF FF E8 64 FD FF FF E8 BB ED FF FF 8D 40  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Explosion_1000
{
strings:
		$a0 = { E8 ?? ?? 5E 1E 06 50 81 ?? ?? ?? 56 FC B8 21 35 CD 21 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 26 ?? ?? ?? ?? ?? ?? 74 ?? 8C D8 48 8E D8  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_21_Dll__aPlib_0_43_____ap0x_____Sign_By_fly___20080504
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 74 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 D6 05 00 00 EB 0C 8B 85 D2 05 00 00 89 85 D6 05 00 00 E8 4C 01 00 00 8D B5 FE 05 00 00 8D 9D 85 04 00 00 33 FF E8 77 01 00 00 EB 1B 8B 85 D6 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD E2 05 00 00 00 74 0E 83 BD E6 05 00 00 00 74 05 E8 15 02 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 6B 05 00 00 89 85 FA 05 00 00 5B FF B5 FA 05 00 00 56 FF D3 83 C4 08 8B B5 FA 05 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD D6 05 00 00 83 C0 04 89 85 F6 05 00 00 EB 6E 56 FF 95 63 05 00 00 0B C0 75 05 E8 08 03 00 00 85 C0 0F 84 95 00 00 00 89 85 F2 05 00 00 8B C6 EB 2A 8B 85 F6 05 00 00 8B 00 50 FF B5 F2 05 00 00 E8 50 02 00 00 85 C0 74 73 89 07 83 85 F6 05 00 00 04 83 C7 04 8B 85 F6 05 00 00 83 38 00 75 D1 EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD D6 05 00 00 83 C0 04 89 85 F6 05 00 00 80 3E 01 75 8D 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF B5 FA 05 00 00 FF 95 6F 05 00 00 68 ?? ?? ?? ?? 6A 00 FF B5 FA 05 00 00 FF 95 6F 05 00 00 E8 A0 00 00 00 E8 9B 01 00 00 61 E9 ?? ?? ?? ?? ?? 61 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_V2_403____Jitit
{
strings:
		$a0 = { 6A 00 FF 15 20 50 40 00 E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 57 BF 00 00 80 00 39 79 14 77 36 53 56 8B B1 29 04 00 00 8B 41 0C 8B 59 10 03 DB 8A 14 30 83 E2 01 0B D3 C1 E2 07 40 89 51 10 89 41 0C 0F B6 04 30 C1 61 14 08 D1 E8 09 41 10 39  }

condition:
		$a0 at entrypoint
}
	
	
rule CRYPToCRACk_s_PE_Protector_V0_9_2____Lukas_Fleischer_____Sign_By_fly
{
strings:
		$a0 = { E8 01 00 00 00 E8 58 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 37 84 DB 75 33 8B F3 03 ?? ?? 81 3E 50 45 00 00 75 26  }

condition:
		$a0 at entrypoint
}
	
	
rule dePACK____deNULL
{
strings:
		$a0 = { EB 01 DD 60 68 00 ?? ?? ?? 68 ?? ?? ?? 00 E8 ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? D2  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_ASPack_2_12_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB  }

condition:
		$a0 at entrypoint
}
	
	
rule WinZip_32_bit_SFX_v8_x_module
{
strings:
		$a0 = { 53 FF 15 ?? ?? ?? 00 B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 74 01 40 ?? ?? ?? ?? FF 15  }

condition:
		$a0 at entrypoint
}
	
	
rule hmimys_s_PE_Pack_0_1____hmimys
{
strings:
		$a0 = { E8 00 00 00 00 5D 83 ED 05 6A 00 FF 95 E1 0E 00 00 89 85 85 0E 00 00 8B 58 3C 03 D8 81 C3 F8 00 00 00 80 AD 89 0E 00 00 01 89 9D 63 0F 00 00 8B 4B 0C 03 8D 85 0E 00 00 8B 53 08 80 BD 89 0E 00 00 00 75 0C 03 8D 91 0E 00 00 2B 95 91 0E 00 00 89 8D 57 0F 00 00 89 95 5B 0F 00 00 8B 5B 10 89 9D 5F 0F 00 00 8B 9D 5F 0F 00 00 8B 85 57 0F 00 00 53 50 E8 B7 0B 00 00 89 85 73 0F 00 00 6A 04 68 00 10 00 00 50 6A 00 FF 95 E9 0E 00 00 89 85 6B 0F 00 00 6A 04 68 00 10 00 00 68 D8 7C 00 00 6A 00 FF 95 E9 0E 00 00 89 85 6F 0F 00 00 8D 85 67 0F 00 00 8B 9D 73 0F 00 00 8B 8D 6B 0F 00 00 8B 95 5B 0F 00 00 83 EA 0E 8B B5 57 0F 00 00 83 C6 0E 8B BD 6F 0F 00 00 50 53 51 52 56 68 D8 7C 00 00 57 E8 01 01 00 00 8B 9D 57 0F 00 00 8B 03 3C 01 75  }

condition:
		$a0 at entrypoint
}
	
	
rule themida_1_0_0_5____http___www_oreans_com
{
strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44  }

condition:
		$a0 at entrypoint
}
	
	
rule Celsius_Crypt_2_1____Z3r0
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 84 92 44 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 84 92 44 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D C4 92 44 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D AC 92 44 00 89 E5 5D FF E1 90 90 90 90 55 89 E5 5D E9 77 C2 00 00 90 90 90 90 90 90 90 55 89 E5 83 EC 28 8B 45 10 89 04 24 E8 3F 14 01 00 48 89 45 FC 8B 45 0C 48 89 45 F4 8D 45 F4 89 44 24 04 8D 45 FC 89 04 24 E8 12 A3 03 00 8B 00 89 45 F8 8B 45 FC 89 45 F0 C6 45 EF 01 C7 45 E8 00 00 00 00 8B 45 E8 3B 45 F8 73 39 80 7D EF 00 74 33 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 1C 1A 01 00 89 C1 8B 45 08 8B 55 E8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 8D 45 E8 FF 00 EB BF 83 7D F0 00 74 34 80 7D EF 00 74 2E 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 DD 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 EB C6 C7 44 24 04 00 00 00 00 8B 45 10 89 04 24 E8 AE 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 7F 0C 0F B6 45 EF 83 E0 01 88 45 E7 EB 04 C6 45 E7 00 0F B6 45 E7 88 45 EF 0F B6 45 EF C9 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Heloween_1172
{
strings:
		$a0 = { E8 ?? ?? 5E 81 EE ?? ?? 56 50 06 0E 1F 8C C0 01 ?? ?? 01 ?? ?? 80 ?? ?? ?? ?? 8B ?? ?? A3 ?? ?? 8A ?? ?? A2 ?? ?? B8 ?? ?? CD 21 3D  }

condition:
		$a0 at entrypoint
}
	
	
rule E_You_Di_Dai___YueHeiFengGao_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 57 0F 31 8B D8 0F 31 8B D0 2B D3 C1 EA 10 B8 ?? ?? ?? ?? 0F 6E C0 B8 ?? ?? ?? ?? 0F 6E C8 0F F5 C1 0F 7E C0 0F 77 03 C2 ?? ?? ?? ?? ?? FF E0  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_vx_x
{
strings:
		$a0 = { B8 EF BE AD DE 50 6A ?? FF 15 10 19 40 ?? E9 AD FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule CrypKey_V5_6_X_DLL____Kenonic_Controls_Ltd______Sign_By_fly
{
strings:
		$a0 = { 8B 1D ?? ?? ?? ?? 83 FB 00 75 0A E8 ?? ?? ?? ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule STUD_RC4_1_0_Jamie_Edition__ScanTime_UnDetectable____by_MarjinZ
{
strings:
		$a0 = { 68 2C 11 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 30 00 00 00 38 00 00 00 00 00 00 00 37 BB 71 EC A4 E1 98 4C 9B FE 8F 0F FA 6A 07 F6 00 00 00 00 00 00 01 00 00 00 20 20 46 6F 72 20 73 74 75 64 00 20 54 6F 00 00 00 00 06 00 00 00 CC 1A 40 00 07 00 00 00 D4 18 40 00 07 00 00 00 7C 18 40 00 07 00 00 00 2C 18 40 00 07 00 00 00 E0 17 40 00 56 42 35 21 F0 1F 2A 00 00 00 00 00 00 00 00 00 00 00 00 00 7E 00 00 00 00 00 00 00 00 00 00 00 00 00 0A 00 09 04 00 00 00 00 00 00 E8 13 40 00 F4 13 40 00 00 F0 30 00 00 FF FF FF 08 00 00 00 01 00 00 00 00 00 00 00 E9 00 00 00 04 11 40 00 04 11 40 00 C8 10 40 00 78 00 00 00 7C 00 00 00 81 00 00 00 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 61 61 61 00 53 74 75 64 00 00 73 74 75 64 00 00 01 00 01 00 30 16 40 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 B4 16 40 00 10 30 40 00 07 00 00 00 24 12 40 00 0E 00 20 00 00 00 00 00 1C 9E 21 00 EC 11 40 00 5C 10 40 00 E4 1A 40 00 2C 34 40 00 68 17 40 00 58 17 40 00 78 17 40 00 8C 17 40 00 8C 10 40 00 62 10 40 00 92 10 40 00 F8 1A 40 00 24 19 40 00 98 10 40 00 9E 10 40 00 77 04 18 FF 04 1C FF 05 00 00 24 01 00 0D 14 00 78 1C 40 00 48 21 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___4_x___LCC_Win32_1_x_
{
strings:
		$a0 = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB  }

condition:
		$a0 at entrypoint
}
	
	
rule BeRoEXEPacker_v1_00_rule__LZBRR_____BeRo___Farbrausch
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 ?? ?? ?? ?? 73 F6 33 C9 E8 ?? ?? ?? ?? 73 1C 33 C0 E8 ?? ?? ?? ?? 73 23 B3 02 41 B0 10  }

condition:
		$a0 at entrypoint
}
	
	
rule NoodleCrypt_v2_00__Eng_____NoodleSpa
{
strings:
		$a0 = { EB 01 9A E8 76 00 00 00 EB 01 9A E8 65 00 00 00 EB 01 9A E8 7D 00 00 00 EB 01 9A E8 55 00 00 00 EB 01 9A E8 43 04 00 00 EB 01 9A E8 E1 00 00 00 EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 9A E8 25 00 00 00 EB 01 9A E8 02  }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor_Light_V1_6_0_1____CGSoftLabs_____Sign_By_fly___20080308
{
strings:
		$a0 = { 55 8B EC 81 EC 68 02 00 00 53 56 57 83 A5 D0 FD FF FF 00 F3 EB 0C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 78 60 00 75 14 6A 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? E8 9C FF FF FF A3 ?? ?? ?? ?? 68 04 01 00 00 8D 85 F0 FD FF FF 50 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8D 84 05 EF FD FF FF 89 85 DC FD FF FF 8B 85 DC FD FF FF 0F BE 00 83 F8 5C 74 0F 8B 85 DC FD FF FF 48 89 85 DC FD FF FF EB E3 8B 85 DC FD FF FF 40 89 85 DC FD FF FF 8B 85 DC FD FF FF 8D 8D F0 FD FF FF 2B C1 89 85 B4 FD FF FF 8B 8D B4 FD FF FF 8D B5 F0 FD FF FF 8D BD FC FE FF FF 8B C1 C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 85 B4 FD FF FF 80 A4 05 FD FE FF FF 00 83 A5 E0 FD FF FF 00 A1 ?? ?? ?? ?? 8B 40 04 25 ?? ?? ?? ?? 85 C0 75 11 A1 ?? ?? ?? ?? 8B 40 04 25 00 00 00 02 85 C0 74 2A E8 5B 06 00 00 89 85 E0 FD FF FF A1 ?? ?? ?? ?? 8B 40 04 25 ?? ?? ?? ?? 85 C0 74 0E 83 BD E0 FD FF FF 00 74 05 E9 34 06 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule ANDpakk2__apk2__V0_18____Dmitry__AND__Andreev_____Sign_By_fly___20080731
{
strings:
		$a0 = { FC BE ?? ?? ?? ?? BF ?? ?? ?? ?? 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 4D D1 F8 8B E8 EB 09 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 13 C9 75 1A 41 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 73 EA 83 C1 02 81 FD ?? ?? ?? ?? 83 D1 01 56 8D 34 2F F3 A4 5E E9 73 FF FF FF C3  }

condition:
		$a0 at entrypoint
}
	
	
rule CrypWrap_vx_x
{
strings:
		$a0 = { E8 B8 ?? ?? ?? E8 90 02 ?? ?? 83 F8 ?? 75 07 6A ?? E8 ?? ?? ?? ?? FF 15 49 8F 40 ?? A9 ?? ?? ?? 80 74 0E  }

condition:
		$a0 at entrypoint
}
	
	
rule InterLok_V5_X____PACE_Anti_Piracy_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC 81 EC A4 00 00 00 53 56 33 F6 57 39 35 ?? ?? ?? ?? 75 53 8D 45 DC 6A 1C 50 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 05 8B 45 E0 EB 22 8B 7D 08 6A 02 57 FF 15 ?? ?? ?? ?? 85 C0 75 0B 66 81 3F 4D 5A 75 04 8B C7 EB 07 56 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B 48 3C 03 C8 89 ?? ?? ?? ?? ?? EB 06 8B ?? ?? ?? ?? ?? 66 8B 59 16 C1 EB 0D 83 E3 01 74 0A 83 7D 0C 01 0F 85 38 01 00 00 8D 45 F8 50 8D 45 FC 50 E8 47 01 00 00 8B F8 59 3B FE 59 75 52 83 7D FC FF FF 75 F8 75 17 8D 85 5C FF FF FF 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 C4 0C EB 18 FF 75 FC 8D 85 5C FF FF FF 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 C4 10 6A 30 8D 85 5C FF FF FF 68 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? E9 BB 00 00 00 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 57 FF D7 57 6A 01 8B F0 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 F6 0F 84 96 00 00 00 83 FE F6 7F 32 74 29 83 FE 97 74 75 83 FE F3 74 18 83 FE F4 74 0C 83 FE F5 75 2B B8 ?? ?? ?? ?? EB 4F B8 ?? ?? ?? ?? EB 48 B8 ?? ?? ?? ?? EB 41 B8 ?? ?? ?? ?? EB 3A 83 FE FA 74 30 83 FE FC 74 24 83 FE FD 74 18 56 8D 45 E0 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 C4 0C 8D 45 E0 EB 13 B8 ?? ?? ?? ?? EB 0C B8 ?? ?? ?? ?? EB 05 B8 ?? ?? ?? ?? 6A 30 68 ?? ?? ?? ?? 50 6A 00 FF 15 ?? ?? ?? ?? 85 DB 75 08 6A 01 FF 15 ?? ?? ?? ?? 33 C0 5F 5E 5B C9 C2 0C 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Gleam_v1_00
{
strings:
		$a0 = { 83 EC 0C 53 56 57 E8 24 02 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_20__Eng_____dulek_xt_____Borland_C___
{
strings:
		$a0 = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6  }

condition:
		$a0 at entrypoint
}
	
	
rule SOFTWrapper_for_Win9x_NT__Evaluation_Version_
{
strings:
		$a0 = { E8 00 00 00 00 5D 8B C5 2D ?? ?? ?? 00 50 81 ED 05 00 00 00 8B C5 2B 85 03 0F 00 00 89 85 03 0F 00 00 8B F0 03 B5 0B 0F 00 00 8B F8 03 BD 07 0F 00 00 83 7F 0C 00 74 2B 56 57 8B 7F 10 03 F8 8B 76 10 03 F0 83 3F 00 74 0C 8B 1E 89 1F 83 C6 04 83 C7 04 EB EF 5F 5E 83 C6 14 83 C7 14 EB D3 00 00 00 00 8B F5 81 C6 0D 0A 00 00 B9 0C 00 00 00 8B 85 03 0F 00 00 01 46 02 83 C6 06 E2 F8 E8 06 08 00 00 68 00 01 00 00 8D 85 DD 0D 00 00 50 6A 00 E8 95 09 00 00 8B B5 03 0F 00 00 66 81 3E 4D 5A 75 33 03 76 3C 81 3E 50 45 00 00 75 28 8B 46 28 03 85 03 0F 00 00 3B C5 74 1B 6A 30 E8 99 09 00 00 6A 30 8D 85 DD 0D 00 00 50 8D 85 2B 0F 00 00 E9 55 03 00 00 66 8B 85 9D 0A 00 00 F6 C4 80 74 31 E8 6A 07 00 00 0B C0 75 23 6A 40 E8 69 09 00 00 6A 40 8D 85 DD 0D 00 00 50 8B 9D 17 0F  }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin_v0_1____Cyberbob
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 B3 28 40 00 8B 42 3C 03 C2 89 85 BD 28 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D D1 28 40 00 53 8F 85 C4 27 40 00 BB ?? 00 00 00 B9 A5 08 00 00 8D BD 75 29 40 00 4F 30 1C 39 FE CB E2 F9 68 2D 01 00 00 59 8D BD AA 30 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 07 4F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D C4 28 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 59 81 C1 1D 00 00 00 52 51 C1 E9 05 23 D1 FF  }

condition:
		$a0 at entrypoint
}
	
	
rule InterLok_V5_51____PACE_Anti_Piracy_____Sign_By_fly
{
strings:
		$a0 = { EB 03 ?? ?? ?? 55 EB 03 ?? ?? ?? EB 04 ?? EB 06 ?? 8B EC EB F9 ?? EB 02 ?? ?? 81 EC A8 00 00 00 EB 02 ?? ?? EB 01 ?? 53 EB 03 ?? ?? ?? EB 05 ?? ?? EB 15 ?? EB 03 ?? ?? ?? 56 EB 04 ?? EB F2 ?? EB 01 ?? EB F8 ?? ?? ?? EB 0F ?? 33 F6 EB 10 ?? ?? ?? EB F7 ?? ?? EB FA ?? EB 01 ?? EB F8 ?? EB 01 ?? 57 EB 03 ?? ?? ?? EB 11 ?? ?? ?? EB 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 08 ?? EB F0 ?? EB 07 ?? ?? EB FA ?? ?? ?? EB 02 ?? ?? BB ?? ?? ?? ?? EB 03 ?? ?? ?? 0F 85 ?? ?? ?? ?? EB 07  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__ExeSmasher______Anorganix
{
strings:
		$a0 = { 9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B E9  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__LCC_Win32_DLL______Anorganix
{
strings:
		$a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 ?? ?? ?? ?? E9  }

condition:
		$a0 at entrypoint
}
	
	
rule CD_Cops_II
{
strings:
		$a0 = { 53 60 BD ?? ?? ?? ?? 8D 45 ?? 8D 5D ?? E8 ?? ?? ?? ?? 8D  }

condition:
		$a0 at entrypoint
}
	
	
rule WinUpack_v0_39_final__relocated_image_base_____By_Dwing__c_2005__h2_
{
strings:
		$a0 = { 60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB AD 8D 6E 10 01 5D 00 8D 7D 1C B5 ?? F3 AB 5E AD 53 50 51 97 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72  }

condition:
		$a0 at entrypoint
}
	
	
rule NsPack_V1_4____LiuXingPing_____Sign_By_fly
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Spalsher_v1_0___v3_0
{
strings:
		$a0 = { 9C 60 8B 44 24 24 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 50 E8 ED 02 ?? ?? 8C C0 0F 84  }

condition:
		$a0 at entrypoint
}
	
	
rule PECompact_v2_00_alpha_38
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 80 B8 BF 10 00 10 01 74 7A C6 80 BF 10 00 10 01 9C 55 53 51 57 52 56 8D 98 0F 10 00 10 8B 53 14 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 8B F8 50 8B 33 8B 53 14 03 F2 8B 4B 0C 03 CA 8D 85 B7 10 00 10 FF 73 04 8F 00 50 57 56 FF D1 58 03 43 08 8B F8 8B 53 14 8B F0 8B 46 FC 83 C0 04 2B F0 89 56 08 8B 4B 10 89 4E 18 FF D7 89 85 BB 10 00 10 5E 5A 5F 59 5B 5D 9D FF E0 8B 80 BB 10 00 10 FF E0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_3_7__2007_06_20_____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 02 ?? ?? E8 2C 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 27 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule yC_v1_3_by_Ashkbiz_Danehkar
{
strings:
		$a0 = { 55 8B EC 81 EC C0 00 00 00 53 56 57 8D BD 40 FF FF FF B9 30 00 00 00 B8 CC CC CC CC F3 AB 60 E8 00 00 00 00 5D 81 ED 84 52 41 00 B9 75 5E 41 00 81 E9 DE 52 41 00 8B D5 81 C2 DE 52 41 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_Basic_v6_0_DLL
{
strings:
		$a0 = { 5A 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 E9 ?? ?? FF  }

condition:
		$a0 at entrypoint
}
	
	
rule Private_Exe_Protector_1_x____setisoft
{
strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? 90 01 ?? BE ?? 10 40 ?? 68 50 91 41 ?? 68 01 ?? ?? ?? C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v3_00
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 33 C9  }

condition:
		$a0 at entrypoint
}
	
	
rule WIBU_Key_V4_10A____WIBU_SYSTEMS_AG_____Sign_By_fly
{
strings:
		$a0 = { F7 05 ?? ?? ?? ?? FF 00 00 00 75 12  }

condition:
		$a0 at entrypoint
}
	
	
rule InstallAnywhere_6_1____Zero_G_Software_Inc
{
strings:
		$a0 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____bart_xt
{
strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_V0_37____Dwing
{
strings:
		$a0 = { 0B 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 18 10 00 00 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 02 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 14 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00  }
	$a1 = { BE ?? ?? ?? ?? AD 50 FF ?? ?? EB  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Themida_WinLicense_V1_8_X_V1_9_X_DLL____Oreans_Technologies_____Sign_By_fly
{
strings:
		$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D ?? ?? ?? ?? EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 05 89 48 01 61 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Video_Lan_Client_____UnknownCompiler_
{
strings:
		$a0 = { 55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_Basic_v5_0
{
strings:
		$a0 = { FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtect_v1_2x__New_Strain_
{
strings:
		$a0 = { 68 01 ?? ?? ?? E8 01 ?? ?? ?? C3 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Metrowerks_CodeWarrior_v2_0__GUI_
{
strings:
		$a0 = { 55 89 E5 53 56 83 EC 44 55 B8 FF FF FF FF 50 50 68 ?? ?? 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule XComp_XPack_V0_97_V0_98____JoKo_____Sign_By_fly___20080219
{
strings:
		$a0 = { 68 ?? ?? ?? ?? 9C 60 E8 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00  }

condition:
		$a0 at entrypoint
}
	
	
rule XComp_XPack_V0_97_V0_98____JoKo_____Sign_By_fly___20080218
{
strings:
		$a0 = { 68 ?? ?? ?? ?? 9C 60 E8 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_20__Eng_____dulek_xt_____Borland_Delphi___Borland_C___
{
strings:
		$a0 = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB  }

condition:
		$a0 at entrypoint
}
	
	
rule SimplePack_1_11_Method_1____bagierule__TMX_
{
strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA BD 00 00 ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 74 55 0F B7 47 22 09 C0 74 4D 6A 04 68 00 10 00 00 FF 77 10 6A 00 FF 93 38 03 00 00 50 56 57 89 EE 03 77 0C 8B 4F 10 89 C7 89 C8 C1 E9 02 FC F3 A5 89 C1 83 E1 03 F3 A4 5F 5E 8B 04 24 89 EA 03 57 0C E8 3F 01 00 00 58 68 00 40 00 00 FF 77 10 50 FF 93 3C 03 00 00 83 C7 28 4E 75 9E BE ?? ?? ?? ?? 09 F6 0F 84 0C 01 00 00 01 EE 8B 4E 0C 09 C9 0F 84 FF 00 00 00 01 E9 89 CF 57 FF 93 30 03 00 00 09 C0 75 3D 6A 04 68 00 10 00 00 68 00 10 00 00 6A 00 FF 93 38 03 00 00 89 C6 8D 83 6F 02 00 00 57 50 56 FF 93 44 03 00 00 6A 10 6A 00 56 6A 00 FF 93 48 03 00 00 89 E5  }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor_V1_0____CGSoftLabs_____Sign_By_fly
{
strings:
		$a0 = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 00 00 E9 E9 02 00 00 E9 EF 0B 00 00 E9 1B 0D 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule ORiEN_v2_11__DEMO_
{
strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE CE 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F 74 65 63 74 69 6F 6E 20 73 79 73 74 65 6D 20 2D 0D 0A 2D 2D 2D 2D 2D 2D 20 43 72 65 61 74 65 64 20 62 79 20 41 2E 20 46 69 73 75 6E 2C 20 31 39 39 34 2D 32 30 30 33 20 2D 2D 2D 2D 2D 2D 0D 0A 2D 2D 2D 2D 2D 2D 2D 20 57 57 57 3A 20 68 74 74 70 3A 2F 2F 7A 61 6C 65 78 66 2E 6E 61 72 6F 64 2E 72 75 2F 20 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 20 65 2D 6D 61 69 6C 3A 20 7A 61 6C 65 78 66 40 68 6F 74 6D 61 69 6C 2E 72 75 20 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_V0_28_V0_399____Dwing_____Sign_By_fly___20080321
{
strings:
		$a0 = { 60 E8 09 00 00 00 ?? ?? ?? ?? E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB AD 8D 6E 10 01 5D 00 8D 7D 1C B5 1C F3 AB 5E AD 53 50 51 97 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 03 B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 01 E3 29 8B D7 2B 55 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 56 08 33 C9 FF 66 1C B1 30 8B 5D 0C 03 D1 FF 16 73 4C 03 D1 FF 16 72 19 03 D1 FF 16 72 29 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 45 0C 8A 00 FF 66 18 83 C2 60 FF 16 87 5D 10 73 0C 03 D1 FF 16 87 5D 14 73 03 87 5D 18 3C 07 B0 08 72 02 B0 0B 50 53 8B D5 03 56 38 FF 56 0C 5B 91 FF 66 30 3C 07 B0 07 72 02 B0 0A 50 87 5D 10 87 5D 14 89 5D 18 8B D5 03 56 3C FF 56 0C 6A 03 59 50 48 3B C1 72 02 8B C1 C1 E0 06 B1 40 8D 9C 85 7C 03 00 00 FF 56 04 3C 04 8B D8 72 5F 33 DB D1 E8 13 DB 48 43 91 43 D3 E3 80 F9 05 8D 94 9D 7C 01 00 00 76 2E 80 E9 04 33 C0 8B 55 00 D1 6D 08 8B 12 0F CA 2B 55 04 03 C0 3B 55 08 72 07 8B 55 08 40 01 55 04 FF 56 10 E2 E0  }

condition:
		$a0 at entrypoint
}
	
	
rule Crunch_v5____Bit_Arts
{
strings:
		$a0 = { EB 15 03 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 FC 07 00 00 89 85 E8 07 00 00 FF 74 24 2C E8 20 02 00 00 0F 82 94 06 00 00 E8 F3 04 00 00 49 0F 88 88 06 00 00 8B B5 E8 07 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_52b2
{
strings:
		$a0 = { 55 8B EC 6A FF 68 B0 ?? ?? ?? 68 60 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 24  }

condition:
		$a0 at entrypoint
}
	
	
rule MS_Visual_C___v_8_DLL__h_small_sig1_
{
strings:
		$a0 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 ?? ?? ?? FF 5D E9 D6 FE FF FF CC CC CC CC CC  }

condition:
		$a0 at entrypoint
}
	
	
rule HACKSTOP_v1_10p1
{
strings:
		$a0 = { B4 30 CD 21 86 E0 3D 00 03 73 ?? B4 2F CD 21 B4 2A CD 21 B4 2C CD 21 B0 FF B4 4C CD 21 50 B8 ?? ?? 58 EB  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Packer
{
strings:
		$a0 = { FC 8B 35 70 01 40 ?? 83 EE 40 6A 40 68 ?? 30 10  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v1_90b2
{
strings:
		$a0 = { 55 8B EC 6A FF 68 F0 C1 40 00 68 A4 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v1_90b3
{
strings:
		$a0 = { 55 8B EC 6A FF 68 08 E2 40 00 68 94 95 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v1_90b1
{
strings:
		$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 04 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v1_90b4
{
strings:
		$a0 = { 55 8B EC 6A FF 68 08 E2 40 00 68 B4 96 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_Microsoft_Visual_C___7_0_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 89 65 00 8B F4 89 3E 56 FF 15 ?? ?? ?? ?? 8B 4E ?? 89 0D ?? ?? ?? 00 8B 46 00 A3  }

condition:
		$a0 at entrypoint
}
	
	
rule SLVc0deProtector_v0_6____SLV
{
strings:
		$a0 = { E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 97 11 40 00 8D B5 EF 11 40 00 B9 FE 2D 00 00 8B FE AC F8 ?? ?? ?? ?? ?? ?? 90  }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin_v1_1_by_cyberbob
{
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 C3 4B 40 00 8B 42 3C 03 C2 89 85 CD 4B 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 9A EB FB 00 83 04 24 0C C3 3B 8B 59 10 03 DA 8B 1B 89 9D E1 4B 40 00 53 8F 85 D7 49 40 00 BB ?? 00 00 00 B9 FE 11 00 00 8D BD 71 4C 40 00 4F EB 07 FA EB 01 FF EB 04 E3 EB F8 69 30 1C 39 FE CB 49 9C  }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin_V1_1____cyberbob_____Sign_By_fly___20080311
{
strings:
		$a0 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 ?? 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 00 EB FB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 ?? ?? ?? ?? ?? ?? F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 ?? EB FB  }

condition:
		$a0 at entrypoint
}
	
	
rule Stranik_1_3_Modula_C_Pascal
{
strings:
		$a0 = { E8 ?? ?? FF FF E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 ?? ?? ?? 00 ?? ?? 00 ?? 00 ?? 00 00 ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C__
{
strings:
		$a0 = { 8B 44 24 08 56 83 E8 ?? 74 ?? 48 75  }
	$a1 = { 8B 44 24 08 83 ?? ?? 74  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule PocketPC_MIB
{
strings:
		$a0 = { E8 FF BD 27 14 00 BF AF 18 00 A4 AF 1C 00 A5 AF 20 00 A6 AF 24 00 A7 AF ?? ?? ?? 0C 00 00 00 00 18 00 A4 8F 1C 00 A5 8F 20 00 A6 8F ?? ?? ?? 0C 24 00 A7 8F ?? ?? ?? 0C 25 20 40 00 14 00 BF 8F 08 00 E0 03 18 00 BD 27 ?? FF BD 27 18 00 ?? AF ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule PECrc32_V0_88____ZhouJinYu
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED B6 A4 45 00 8D BD B0 A4 45 00 81 EF 82 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__PE_Pack_0_99______Anorganix
{
strings:
		$a0 = { 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A E9  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX___ECLiPSE_layer
{
strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 D2 EB 01 0F 56 EB 01 0F E8 03 00 00 00 EB 01 0F EB 01 0F 5E EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule Unknown_Joiner__sign_from_pinch_26_03_2007_02_12_
{
strings:
		$a0 = { 44 90 4C 90 B9 DE 00 00 00 BA 00 10 40 00 83 C2 03 44 90 4C B9 07 00 00 00 44 90 4C 33 C9 C7 05 08 30 40 00 00 00 00 00 90 68 00 01 00 00 68 21 30 40 00 6A 00 E8 C5 02 00 00 90 6A 00 68 80  }

condition:
		$a0 at entrypoint
}
	
	
rule _EPack_1_4_lite__final____by_6aHguT
{
strings:
		$a0 = { 33 C0 8B C0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule MEW_10_by_Northfox
{
strings:
		$a0 = { 33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_20_Dll__aPlib_0_43_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 6F 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 92 05 00 00 EB 0C 8B 85 8E 05 00 00 89 85 92 05 00 00 8D B5 BA 05 00 00 8D 9D 41 04 00 00 33 FF E8 38 01 00 00 EB 1B 8B 85 92 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 9E 05 00 00 00 74 0E 83 BD A2 05 00 00 00 74 05 E8 D6 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 27 05 00 00 89 85 B6 05 00 00 5B FF B5 B6 05 00 00 56 FF D3 83 C4 08 8B B5 B6 05 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 92 05 00 00 83 C0 04 89 85 B2 05 00 00 EB 6E 56 FF 95 1F 05 00 00 0B C0 75 05 E8 C9 02 00 00 85 C0 0F 84 94 00 00 00 89 85 AE 05 00 00 8B C6 EB 2A 8B 85 B2 05 00 00 8B 00 50 FF B5 AE 05 00 00 E8 11 02 00 00 85 C0 74 72 89 07 83 85 B2 05 00 00 04 83 C7 04 8B 85 B2 05 00 00 83 38 00 75 D1 EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD 92 05 00 00 83 C0 04 89 85 B2 05 00 00 80 3E 01 75 8D 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 B6 05 00 00 FF 95 2B 05 00 00 68 00 80 00 00 6A 00 FF B5 B6 05 00 00 FF 95 2B 05 00 00 E8 61 00 00 00 E8 5C 01 00 00 61 E9 ?? ?? ?? ?? 61 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule ILUCRYPT_v4_015_rule__exe_
{
strings:
		$a0 = { 8B EC FA C7 46 F7 ?? ?? 42 81 FA ?? ?? 75 F9 FF 66 F7  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__PENightMare_2_Beta______Anorganix
{
strings:
		$a0 = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___v6_0
{
strings:
		$a0 = { 55 8B EC 83 EC 50 53 56 57 BE ?? ?? ?? ?? 8D 7D F4 A5 A5 66 A5 8B  }
	$a1 = { 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? 0D ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 1C ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00  }
	$a2 = { 55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC ?? 53 56 57 89 65 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule Vcasm_Protector_1_0
{
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83  }

condition:
		$a0 at entrypoint
}
	
	
rule Alloy_v1_x_2000
{
strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 46 23 40 ?? 0B  }

condition:
		$a0 at entrypoint
}
	
	
rule Private_Personal_Packer__PPP__1_0_3____ConquestOfTroy_com
{
strings:
		$a0 = { E8 19 00 00 00 90 90 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 E8 D3 03 00 00 A3 20 37 00 10 50 6A 00 E8 DE 03 00 00 A3 24 37 00 10 FF 35 20 37 00 10 6A 00 E8 EA 03 00 00 A3 30 37 00 10 FF 35 24 37 00 10 E8 C2 03 00 00 A3 28 37 00 10 8B 0D 30 37 00 10 8B 3D 28 37 00 10 EB 09 49 C0 04 39 55 80 34 39 24 0B C9  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_Delphi_v5_0_KOL_MCK
{
strings:
		$a0 = { 55 8B EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule StarForce_V1_X_V3_X____StarForce_Copy_Protection_System
{
strings:
		$a0 = { 68 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___v4_x
{
strings:
		$a0 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 00 00 00 00 83 EC ?? 53 56 57  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_Modified_Stub_b____Farb_rausch_Consumer_Consulting
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC  }

condition:
		$a0 at entrypoint
}
	
	
rule EXEPACK_v4_05__v4_06
{
strings:
		$a0 = { 8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 06 ?? ?? 8E C0 8B 0E ?? ?? 8B F9 4F 8B F7 FD F3 A4  }

condition:
		$a0 at entrypoint
}
	
	
rule ORiEN_v2_11___2_12____Fisun_Alexander
{
strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE ?? 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F  }

condition:
		$a0 at entrypoint
}
	
	
rule kkrunchy_V0_2X____Ryd_____Sign_By_fly
{
strings:
		$a0 = { BD ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? ?? 57 BE ?? ?? ?? ?? 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6  }

condition:
		$a0 at entrypoint
}
	
	
rule CipherWall_Self_Extrator_Decryptor__Console__v1_5
{
strings:
		$a0 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 0B 6E 5B 9B 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF 5E 89 F7 B9 12 10 00 00 8A 07 47 2C E8 3C 01 77 F7 80 3F 06 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4  }

condition:
		$a0 at entrypoint
}
	
	
rule RE_Crypt_v0_7x____Crudd_rule__RET___h2_
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B 17 33 55 58 89 17 83 C7 04 83 C1 FC EB EC 8B  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Armadillo_3_00______Anorganix
{
strings:
		$a0 = { 60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE32_V1_1____PKWARE_Inc_
{
strings:
		$a0 = { 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 00 00 00 00 E8 ?? ?? ?? ?? E9  }

condition:
		$a0 at entrypoint
}
	
	
rule Inno_Setup_Module_v1_2_9
{
strings:
		$a0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 EC 89 45 C0 E8 5B 73 FF FF E8 D6 87 FF FF E8 C5 A9 FF FF E8 E0  }

condition:
		$a0 at entrypoint
}
	
	
rule Reg2Exe_2_24___by_Jan_Vorel
{
strings:
		$a0 = { 6A 00 E8 CF 20 00 00 A3 F4 45 40 00 E8 CB 20 00 00 6A 0A 50 6A 00 FF 35 F4 45 40 00 E8 07 00 00 00 50 E8 BB 20 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 F8 45 40 00 E8 06 19 00 00 83 C4 0C 8B 44 24 04 A3 FC 45 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 8C 20 00 00 A3 F8 45 40 00 E8 02 20 00 00 E8 32 1D 00 00 E8 20 19 00 00 E8 A3 16 00 00 68 01 00 00 00 68 38 46 40 00 68 00 00 00 00 8B 15 38 46 40 00 E8 71 4F 00 00 B8 00 00 10 00 BB 01 00 00 00 E8 82 4F 00 00 FF 35 48 41 40 00 B8 00 01 00 00 E8 9D 15 00 00 8D 0D 1C 46 40 00 5A E8 82 16 00 00 68 00 01 00 00 FF 35 1C 46 40 00 E8 24 20 00 00 A3 24 46 40 00 FF 35 48 41 40 00 FF 35 24 46 40 00 FF 35 1C 46 40 00 E8 DC 10 00 00 8D 0D 14 46 40 00 5A E8 4A 16  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___v4_2
{
strings:
		$a0 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 ?? ?? ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 ?? ?? FF  }
	$a1 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 ?? ?? ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 ?? ?? C7  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule RLPack_V1_18_Dll__LZMA_4_30_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 9F 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 08 83 3C 37 00 75 E6 83 BD 0D 0B 00 00 00 74 0E 83 BD 11 0B 00 00 00 74 05 E8 F6 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 AA 0A 00 00 89 85 1D 0B 00 00 5B 60 FF B5 F9 0A 00 00 56 FF B5 1D 0B 00 00 FF D3 61 8B B5 1D 0B 00 00 8B C6 EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor_Standard_V1_6_0_1____CGSoftLabs_____Sign_By_fly___20080308
{
strings:
		$a0 = { 55 8B EC 81 EC 74 02 00 00 53 56 57 83 A5 C8 FD FF FF 00 F3 EB 0C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 40 04 25 ?? ?? ?? ?? 85 C0 74 5C 83 7D 0C 01 75 2A 8B 45 08 A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? 75 19 6A 04 68 00 10 00 00 68 20 03 00 00 6A 00 FF ?? ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 7D 0C 00 75 0E 83 3D ?? ?? ?? ?? ?? 74 05 E9 F4 0A 00 00 83 3D ?? ?? ?? ?? ?? 74 05 E9 BB 09 00 00 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 78 60 00 75 1C 6A 10 6A 00 E8 E8 19 00 00 59 50 6A 01 E8 DF 19 00 00 59 50 6A 00 FF 15 ?? ?? ?? ?? E8 27 FF FF FF A3 ?? ?? ?? ?? 6A 04 68 00 10 00 00 68 80 00 00 00 6A 00 FF 15 ?? ?? ?? ?? 89 85 E8 FD FF FF 68 04 01 00 00 8D 85 F0 FD FF FF 50 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8D 84 05 EF FD FF FF 89 85 D4 FD FF FF 8B 85 D4 FD FF FF 0F BE 00 83 F8 5C 74 0F 8B 85 D4 FD FF FF 48 89 85 D4 FD FF FF EB E3 8B 85 D4 FD FF FF 40 89 85 D4 FD FF FF 8B 85 D4 FD FF FF 8D 8D F0 FD FF FF 2B C1 89 85 AC FD FF FF 8B 8D AC FD FF FF 8D B5 F0 FD FF FF 8D BD FC FE FF FF 8B C1 C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 85 AC FD FF FF 80 A4 05 FD FE FF FF 00 83 A5 D8 FD FF FF 00 A1 ?? ?? ?? ?? 8B 40 04 25 ?? ?? ?? ?? 85 C0 75 11 A1 ?? ?? ?? ?? 8B 40 04 25 ?? ?? ?? ?? 85 C0 74 43 E8 11 0C 00 00 89 85 D8 FD FF FF A1 ?? ?? ?? ?? 8B 40 04 25 ?? ?? ?? ?? 85 C0 74 27 83 BD D8 FD FF FF 00 74 1E 6A 10 FF B5 D4 FD FF FF 6A 18 E8 C3 18 00 00 59 50 6A 00 FF 15 ?? ?? ?? ?? E9 8F 09 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_C___for_Win32_1994
{
strings:
		$a0 = { A1 ?? ?? ?? ?? C1 ?? ?? A3 ?? ?? ?? ?? 83 ?? ?? ?? ?? 75 ?? 57 51 33 C0 BF  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_C___for_Win32_1995
{
strings:
		$a0 = { A1 ?? ?? ?? ?? C1 ?? ?? A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76  }
	$a1 = { A1 ?? ?? ?? ?? C1 ?? ?? A3 ?? ?? ?? ?? 83 ?? ?? ?? ?? 75 ?? 80 ?? ?? ?? ?? ?? ?? 74  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Gleam_1_00______Anorganix
{
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF E9  }

condition:
		$a0 at entrypoint
}
	
	
rule R_SC_s_Process_Patcher_v1_4
{
strings:
		$a0 = { E8 E1 01 00 00 80 38 22 75 13 80 38 00 74 2E 80 38 20 75 06 80 78 FF 22 74 18 40 EB ED 80 38 00 74 1B EB 19 40 80 78 FF 20 75 F9 80 38 00 74 0D EB 0B 40 80 38 00 74 05 80 38 22 74 00 8B F8 B8 04 60 40 00 68 00 20 40 00 C7 05 A2 20 40 00 44 00 00 00 68 92 20 40 00 68 A2 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 7C 01 00 00 85 C0 0F 84 2A 01 00 00 B8 00 60 40 00 8B 00 A3 1C 22 40 00 BE 40 60 40 00 83 7E FC 00 0F 84 F6 00 00 00 8B 3E 83 C6 04 85 FF 0F 84 83 00 00 00 81 FF 72 21 73 63 0F 84 DD 00 00 00 33 DB 66 8B 1E 8B CF 8D 7E 02 C7 05 EA 21 40 00 00 00 00 00 83 05 EA 21 40 00 01 50 A1 1C 22 40 00 39 05 EA 21 40 00 58 0F 84 C1 00 00 00 60 6A 00 53 68 EA 20 40 00 51 FF 35 92 20 40 00 E8 EB 00 00 00 61 60 FC BE EA 20 40 00 8B CB F3 A6 61 75 C2 03  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_v0_89_6___v1_02___v1_05___v1_22
{
strings:
		$a0 = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC  }

condition:
		$a0 at entrypoint
}
	
	
rule nPack_V1_1_150_2006_Beta____NEOx_____Sign_By_fly
{
strings:
		$a0 = { 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 56 57 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B F8 68 ?? ?? ?? ?? 57 FF D6 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 5F A3 ?? ?? ?? ?? 5E C3  }

condition:
		$a0 at entrypoint
}
	
	
rule SEA_AXE
{
strings:
		$a0 = { FC BC ?? ?? 0E 1F E8 ?? ?? 26 A1 ?? ?? 8B 1E ?? ?? 2B C3 8E C0 B1 ?? D3 E3  }

condition:
		$a0 at entrypoint
}
	
	
rule Ding_Boy_s_PE_lock_Phantasm_v1_5b3
{
strings:
		$a0 = { 9C 55 57 56 52 51 53 9C FA E8 00 00 00 00 5D 81 ED 5B 53 40 00 B0  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__MEW_11_SE_1_0______Anorganix
{
strings:
		$a0 = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule UnoPiX_0_75____BaGiE
{
strings:
		$a0 = { 60 E8 07 00 00 00 61 68 ?? ?? 40 00 C3 83 04 24 18 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 61  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_v0_38_beta____Dwing
{
strings:
		$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 38 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 D2 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B 7E 34 0F 82 97 FE FF FF 58 5F 59 E3 1B 8A 07 47 04 18 3C 02 73 F7 8B 07 3C ?? 75 F1 B0 00 0F C8 03 46 38 2B C7 AB E2 E5 5E 5D 59 51 59 46 AD 85 C0 74 1F  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_v2_61
{
strings:
		$a0 = { 55 8B EC 6A FF 68 28 ?? ?? ?? 68 E4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 0C  }

condition:
		$a0 at entrypoint
}
	
	
rule KenPack_V0_7____CHKen_Com_____Sign_By_fly___20090610
{
strings:
		$a0 = { E8 0E 00 00 00 8D 4A 14 58 51 64 8B 08 FF 31 89 21 89 10 5A 6A 18 FF E2 72 8B 44 24 0C 8B ?? A8 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 89 E5 31 C9 31 C0 ?? ?? B4 04 50 E2 FD 41 51 51 51 51 49 51 6A FF 89 E3 ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? ?? E8 7B 00 00 00 B1 08 FF 16 8D 52 04 B0 01 73 0B FF 16 B0 09 73 05 C1 E1 05 B0 11 50 8D 2C 82 FF 56 04 5D 01 E8 C3 31 C0 40 8D 54 85 00 FF 16 11 C0 39 C8 72 F4 29 C8 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule ASProtect_v2_0
{
strings:
		$a0 = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2C  }

condition:
		$a0 at entrypoint
}
	
	
rule Splash_Bitmap_v1_00_____BoB___Bobsoft
{
strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 6A 00  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__JDPack_1_x___JDProtect_0_9______Anorganix
{
strings:
		$a0 = { 60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 E9  }

condition:
		$a0 at entrypoint
}
	
	
rule VProtector_V1_0E____vcasm
{
strings:
		$a0 = { EB 0A 5B 56 50 72 6F 74 65 63 74 5D E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Molebox_Ultra_V4_0_X____Teggo_Software_Ltd______Sign_By_fly___20090518
{
strings:
		$a0 = { 55 89 E5 E8 0C 00 00 00 5D C3 CC CC CC CC CC E8 85 08 00 00 6A 00 54 6A 00 E8 8E 04 00 00 87 04 24 E8 90 06 00 00 5F 5E 5E 89 EC 5D FF E0 32 06 74 07 32 26 74 03 31 C0 C3 C1 E8 10 83 C6 02 09 C0 75 EB B8 01 00 00 00 C3 31 C0 8B 74 24 10 8B 76 28 66 8B 06 83 C6 02 09 C0 74 09 83 F0 5C 75 02 89 F7 EB ED 89 FE C3 56 57 E8 DA FF FF FF B8 6E 4E 74 54 E8 B5 FF FF FF 09 C0 74 0E B8 64 44 6C 4C E8 A7 FF FF FF 09 C0 74 00 5F 5E C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__VirusConstructor_based
{
strings:
		$a0 = { BB ?? ?? B9 ?? ?? 2E ?? ?? ?? ?? 43 43 ?? ?? 8B EC CC 8B ?? ?? 81 ?? ?? ?? 06 1E B8 ?? ?? CD 21 3D ?? ?? ?? ?? 8C D8 48 8E D8  }
	$a1 = { E8 ?? ?? 5D 81 ?? ?? ?? 06 1E E8 ?? ?? E8 ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? ?? B4 4A BB FF FF CD 21 83 ?? ?? B4 4A CD 21  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Obsidium_1_3_0_13____Obsidium_Software
{
strings:
		$a0 = { EB 01 ?? E8 26 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 02 ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 03 ?? ?? ?? E8 13 26 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_V0_24_V0_28____Dwing_____Sign_By_fly___20080321
{
strings:
		$a0 = { BE ?? ?? ?? ?? AD 8B F8 95 AD 91 F3 A5 AD ?? ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF ?? ?? ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 01 E3 29 8B D7 2B 55 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 56 08 33 C9 FF 66 24 B1 30 8B 5D 0C 03 D1 FF 16 73 4B 03 D1 FF 16 72 19 03 D1 FF 16 72 29 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 45 0C 8A 00 FF 66 20 83 C2 60 FF 16 87 5D 10 73 0C 03 D1 FF 16 87 5D 14 73 03 87 5D 18 3C 07 B0 08 72 02 B0 0B 50 53 8B D5 03 56 14 FF 56 0C 5B 91 FF 66 3C 07 B0 07 72 02 B0 0A 50 87 5D 10 87 5D 14 89 5D 18 8B D5 03 56 18 FF 56 0C  }

condition:
		$a0 at entrypoint
}
	
	
rule MPRESS_V0_71a_V0_75b____MATCODE_Software_____Sign_By_fly___20080310
{
strings:
		$a0 = { 57 56 53 51 52 55 E8 10 00 00 00 E8 7A 00 00 00 5D 5A 59 5B 5E 5F E9 84 01 00 00 E8 00 00 00 00 58 05 84 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 AD 2B C8 03 F1 8B C8 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 AC 0A C0 74 37 8A C8 24 3F 80 E1 C0 C1 E0 10 66 AD 80 F9 C0 74 1E F6 C1 40 75 0A 8B C8 2B C0 F3 AA 75 FC EB D9 8B D6 8B CF 03 F0 E8 8F 00 00 00 03 F8 EB CA 8B C8 F3 A4 75 FC EB C2 C3 E8 00 00 00 00 5F 81 C7 71 FF FF FF B0 E9 AA B8 9A 01 00 00 AB 2B FF E8 00 00 00 00 58 05 FE 00 00 00 8B 78 08 8B D7 8B 78 04 0B FF 74 53 8B 30 03 F0 2B F2 8B EE 8B C2 8B 45 3C 03 C5 8B 48 34 2B CD 74 3D E8 00 00 00 00 58 05 DD 00 00 00 8B 10 03 F2 03 FE 2B C0 AD 3B F7 73 25 8B D8 AD 3B F7 73 1E 8B D0 83 EA 08 03 D6 66 AD 0A E4 74 0B 25 FF 0F 00 00 03 C3 03 C5 29 08 3B F2 73 D8 EB E9 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_1_1_BasicEdition____ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 4A 02 00 00 8D 9D 11 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68  }

condition:
		$a0 at entrypoint
}
	
	
rule IMPostor_Pack_1_0____Mahdi_Hezavehi
{
strings:
		$a0 = { BE ?? ?? ?? 00 83 C6 01 FF E6 00 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? 02 ?? ?? 00 10 00 00 00 02 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Modification_of_Hi_924
{
strings:
		$a0 = { 50 53 51 52 1E 06 9C B8 21 35 CD 21 53 BB ?? ?? 26 ?? ?? 49 48 5B  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_ZCode_1_01_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35  }

condition:
		$a0 at entrypoint
}
	
	
rule BeRoEXEPacker_v1_00_DLL_rule__LZMA_____BeRo___Farbrausch
{
strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8  }

condition:
		$a0 at entrypoint
}
	
	
rule ICrypt_1_0___by_BuGGz
{
strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 70 3B 00 10 E8 3C FA FF FF 33 C0 55 68 6C 3C 00 10 64 FF 30 64 89 20 6A 0A 68 7C 3C 00 10 A1 50 56 00 10 50 E8 D8 FA FF FF 8B D8 53 A1 50 56 00 10 50 E8 0A FB FF FF 8B F8 53 A1 50 56 00 10 50 E8 D4 FA FF FF 8B D8 53 E8 D4 FA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 64 56 00 10 E8 25 F6 FF FF B8 64 56 00 10 E8 13 F6 FF FF 8B CF 8B D6 E8 E6 FA FF FF 53 E8 90 FA FF FF 8D 4D EC BA 8C 3C 00 10 A1 64 56 00 10 E8 16 FB FF FF 8B 55 EC B8 64 56 00 10 E8 C5 F4 FF FF B8 64 56 00 10 E8 DB F5 FF FF E8 56 FC FF FF 33 C0 5A 59 59 64 89 10 68 73 3C 00 10 8D 45 EC E8 4D F4 FF FF C3 E9 E3 EE FF FF EB F0 5F 5E 5B E8 4D F3 FF FF 00 53 45 54 ?? ?? ?? ?? 00 FF FF FF FF 08 00 00 00 76 6F 74 72 65 63 6C 65  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_3_00a____Silicon_Realms_Toolworks
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_Delphi_DLL
{
strings:
		$a0 = { 55 8B EC 83 C4 B4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 40  }

condition:
		$a0 at entrypoint
}
	
	
rule AHPack_V0_1____FEUERRADER_____Sign_By_fly
{
strings:
		$a0 = { 60 68 54 ?? ?? 00 B8 48 ?? ?? 00 FF 10 68 B3 ?? ?? 00 50 B8 44 ?? ?? 00 FF 10 68 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Microsoft_Visual_C___v6_0__Debug_Version_
{
strings:
		$a0 = { 55 8B EC 51 ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_V2_736____Jitit_____Sign_By_fly
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 58 BB F3 1C 00 00 2B C3 50 68 00 00 40 00 68 00 26 00 00 68 CC 00 00 00 E8 C1 FE FF FF E9 97 FF FF FF CC CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_v0_80___v0_84
{
strings:
		$a0 = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF 75 09 8B 1E 83 EE FC  }

condition:
		$a0 at entrypoint
}
	
	
rule SuckStop_v1_11
{
strings:
		$a0 = { EB ?? ?? ?? BE ?? ?? B4 30 CD 21 EB ?? 9B  }

condition:
		$a0 at entrypoint
}
	
	
rule UnoPiX_1_03_1_10____BaGiE
{
strings:
		$a0 = { 83 EC 04 C7 04 24 00 ?? ?? ?? C3 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 ?? ?? 00 00 10 00 00 00 00 00 00 02 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 10  }

condition:
		$a0 at entrypoint
}
	
	
rule MS_Visual_C___v_8_DLL__h_small_sig2_
{
strings:
		$a0 = { 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 0F 84 ?? ?? 00 00 83 FE 01  }

condition:
		$a0 at entrypoint
}
	
	
rule MEW_11_SE_v1_2____Northfoxrule__HCC_
{
strings:
		$a0 = { E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule GameGuard_v2006_5_x_x____exe_____sign_by_hot_UNP
{
strings:
		$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Upx_v1_2____Marcus___Lazlo
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 05 A4 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 F2 31 C0 40 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 E6 31 C9 83  }

condition:
		$a0 at entrypoint
}
	
	
rule StarForce_ProActive_1_1____StarForce_Technology
{
strings:
		$a0 = { 68 ?? ?? ?? ?? FF 25 ?? ?? 57  }

condition:
		$a0 at entrypoint
}
	
	
rule Exe_Shield_v1_7
{
strings:
		$a0 = { EB 06 68 90 1F 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90  }

condition:
		$a0 at entrypoint
}
	
	
rule WinKript_v1_0____Mr__Crimson
{
strings:
		$a0 = { 33 C0 8B B8 00 ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 83 C0 08 EB D5 61 E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_19__aPlib_0_43_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 48 04 00 00 00 74 0E 83 BD 4C 04 00 00 00 74 05 E8 B8 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 D1 03 00 00 89 85 5C 04 00 00 5B FF B5 5C 04 00 00 56 FF D3 83 C4 08 8B B5 5C 04 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 E9 94 00 00 00 56 FF 95 C9 03 00 00 85 C0 0F 84 B4 00 00 00 89 85 54 04 00 00 8B C6 EB 5B 8B 85 58 04 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 58 04 00 00 C7 00 20 20 20 00 EB 06 FF B5 58 04 00 00 FF B5 54 04 00 00 FF 95 CD 03 00 00 85 C0 74 71 89 07 83 C7 04 8B 85 58 04 00 00 EB 01 40 80 38 00 75 FA 40 89 85 58 04 00 00 66 81 78 02 00 80 74 A5 80 38 00 75 A0 EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 80 3E 01 0F 85 63 FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 5C 04 00 00 FF 95 D5 03 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule NsPack_1_4____Liuxingping
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 ?? ?? 40 00 2D ?? ?? 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoiner_Small__build_029_____GlOFF
{
strings:
		$a0 = { 50 32 C4 8A C3 58 E8 DE FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule MicroDog_Win32Shell_V4_X____SafeNet_____Sign_By_fly
{
strings:
		$a0 = { 60 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 C6 85 ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 33 C0 B9 3F ?? ?? ?? F3 AB C6 85 ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 33 C0 B9 3F ?? ?? ?? F3 AB C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 C7 ?? ?? ?? ?? ?? ?? ?? E9 13 09 00 00 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? 83 ?? ?? ?? 75 05 E9 C1 11 00 00 68 ?? ?? ?? ?? A1 ?? ?? ?? ?? 50 8B ?? ?? 50 E8 ?? ?? ?? ?? 83 ?? ?? A1 ?? ?? ?? ?? 33 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? E9 CE 0E 00 00 E9 36 11 00 00 E9 3D 11 00 00 E9 38 11 00 00 66 ?? ?? ?? ?? ?? EB 04 66 ?? ?? ?? 8B ?? ?? 25 FF FF 00 00 83 ?? ?? 0F 8D DF 00 00 00 8B ?? ?? 25 FF FF 00 00 8B ?? ?? 81 E1 FF FF 00 00 0F AF C1 8B ?? ?? 81 E1 FF FF 00 00 0F AF C1 8B ?? ?? 81 E1 FF FF 00 00 0F AF C1 83 ?? ?? 89 ?? ?? ?? ?? ?? EB 7E  }

condition:
		$a0 at entrypoint
}
	
	
rule WebCops_rule__EXE_____LINK_Data_Security
{
strings:
		$a0 = { EB 03 05 EB 02 EB FC 55 EB 03 EB 04 05 EB FB EB 53 E8 04 00 00 00 72  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__Microsoft_Visual_C___7_0_DLL______Anorganix
{
strings:
		$a0 = { 55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 ?? ?? ?? ?? E9  }

condition:
		$a0 at entrypoint
}
	
	
rule PEQuake_v0_06_by_fORGAT
{
strings:
		$a0 = { E8 A5 00 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 3D ?? 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4A ?? 00 00 5B ?? 00 00 6E ?? 00 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 ?? ?? 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 5D 81 ED 05 00 00 00 8D 75 3D 56 FF 55 31 8D B5 81 00 00 00 56 50 FF 55 2D 89 85 8E 00 00 00 6A 04 68 00 10 00 00 68 ?? ?? 00 00 6A 00 FF 95 8E 00 00 00 50 8B 9D 7D 00 00 00 03 DD 50 53 E8 04 00 00 00 5A 55 FF E2 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB  }

condition:
		$a0 at entrypoint
}
	
	
rule CHECKPRG__c__1992
{
strings:
		$a0 = { 33 C0 BE ?? ?? 8B D8 B9 ?? ?? BF ?? ?? BA ?? ?? 47 4A 74  }

condition:
		$a0 at entrypoint
}
	
	
rule yoda_s_Crypter_v1_3
{
strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 8C 21 40 00 B9 51 2D 40 00 81 E9 E6 21 40 00 8B D5 81 C2 E6 21 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_Stone_s_PE_Encryptor_2_0_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 53 51 52 56 57 55 E8 00 00 00 00 5D 81 ED 42 30 40 00 FF 95 32 35 40 00 B8 37 30 40 00 03 C5 2B 85 1B 34 40 00 89 85 27 34 40 00 83  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Trivial_46
{
strings:
		$a0 = { B4 4E B1 20 BA ?? ?? CD 21 BA ?? ?? B8 ?? 3D CD 21  }

condition:
		$a0 at entrypoint
}
	
	
rule Stone_s_PE_Encryptor_v1_0
{
strings:
		$a0 = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 63 3A 40 ?? 2B 95 C2 3A 40 ?? 83 EA 0B 89 95 CB 3A 40 ?? 8D B5 CA 3A 40 ?? 0F B6 36  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_PEX_0_99_____emadicius
{
strings:
		$a0 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED FF 22 40 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_21__aPlib_0_43_____ap0x_____Sign_By_fly___20080504
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 D6 05 00 00 EB 0C 8B 85 D2 05 00 00 89 85 D6 05 00 00 E8 4C 01 00 00 8D B5 FE 05 00 00 8D 9D 85 04 00 00 33 FF E8 77 01 00 00 EB 1B 8B 85 D6 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD E2 05 00 00 00 74 0E 83 BD E6 05 00 00 00 74 05 E8 15 02 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 6B 05 00 00 89 85 FA 05 00 00 5B FF B5 FA 05 00 00 56 FF D3 83 C4 08 8B B5 FA 05 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD D6 05 00 00 83 C0 04 89 85 F6 05 00 00 EB 6E 56 FF 95 63 05 00 00 0B C0 75 05 E8 08 03 00 00 85 C0 0F 84 95 00 00 00 89 85 F2 05 00 00 8B C6 EB 2A 8B 85 F6 05 00 00 8B 00 50 FF B5 F2 05 00 00 E8 50 02 00 00 85 C0 74 73 89 07 83 85 F6 05 00 00 04 83 C7 04 8B 85 F6 05 00 00 83 38 00 75 D1 EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD D6 05 00 00 83 C0 04 89 85 F6 05 00 00 80 3E 01 75 8D 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF B5 FA 05 00 00 FF 95 6F 05 00 00 68 ?? ?? ?? ?? 6A 00 FF B5 FA 05 00 00 FF 95 6F 05 00 00 E8 A0 00 00 00 E8 9B 01 00 00 61 E9 ?? ?? ?? ?? ?? 61 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule JDProtect_V20081208_demo_____________________Sign_By_fly___20090119
{
strings:
		$a0 = { 10 3C 0C 32 54 50 50 83 2D 51 52 B9 E8 ?? 52 2A 10 16 84 01  }

condition:
		$a0 at entrypoint
}
	
	
rule PKLITE32_v1_1
{
strings:
		$a0 = { 55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 ?? ?? ?? 5D C2 0C ?? 8B 45 0C 57 56 53 8B 5D 10  }
	$a1 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 00 00 00 00 E8  }
	$a2 = { 50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20 31  }
	$a3 = { 55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 00 00 00 5D C2 0C 00 8B 45 0C 57 56 53 8B 5D 10  }
	$a4 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 44 24 0C 50  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint or $a4 at entrypoint
}
	
	
rule MinGW_v3_2_x__WinMain_
{
strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 FC 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 FC 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 18 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 0C 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 53 83 EC 24 C7 04 24 A0 11 40 00 E8 5D 08 00 00 83 EC 04 E8 55 03 00 00 C7 04 24 00 20 40 00 8B 15 10 20 40 00 8D 4D F8 C7 45 F8 00 00 00 00 89 4C 24 10 89 54 24 0C 8D 55 F4 89 54 24 08 C7 44 24 04 04 20 40 00 E8 D2 07 00 00 A1 20 20 40 00 85 C0 74 76 A3 30 20 40 00 A1 08 41 40 00 85 C0 74 1F 89 04 24 E8 93 07 00 00 8B 1D 20 20 40 00 89 04 24 89 5C 24 04 E8 91 07 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule HACKSTOP_v1_11c
{
strings:
		$a0 = { B4 30 CD 21 86 E0 3D ?? ?? 73 ?? B4 ?? CD 21 B0 ?? B4 4C CD 21 53 BB ?? ?? 5B EB  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__SYP
{
strings:
		$a0 = { 47 8B C2 05 1E 00 52 8B D0 B8 02 3D CD 21 8B D8 5A  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Embedded_V2_620_V2_623____Jitit_____Sign_By_fly
{
strings:
		$a0 = { E8 00 00 00 00 58 BB AC 1E 00 00 2B C3 50 68 ?? ?? ?? ?? 68 B0 21 00 00 68 C4 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule mPack_V0_03____DeltaAziz_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC 83 ?? ?? 33 C0 89 45 F0 B8 ?? ?? ?? ?? E8 67 C4 FF FF 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 F0 33 C0 E8 93 C8 FF FF 8B 45 F0 E8 87 CB FF FF A3 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 A1 ?? ?? ?? ?? E8 FA C9 FF FF 83 F8 FF 75 0A E8 88 B2 FF FF E9 1B 01 00 00 C7 05 ?? ?? ?? ?? 32 00 00 00 A1 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 C9 C9 FF FF BA ?? ?? ?? ?? A1 ?? ?? ?? ?? B9 04 00 00 00 E8 C5 C9 FF FF 83 3D ?? ?? ?? ?? 32 77 0A E8 47 B2 FF FF E9 DA 00 00 00 A1 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 92 C9 FF FF BA 18 A5 00 10 A1 ?? ?? ?? ?? B9 04 00 00 00 E8 8E C9 FF FF 83 F8 04 74 0A E8 14 B2 FF FF E9 A7 00 00 00 E8 0A CB FF FF A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? E8 63 C9 FF FF 83 F8 FF 75 0A E8 F1 B1 FF FF E9 84 00 00 00 6A 00 6A 00 B8 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 D4 CD FF FF 84 C0 75 07 E8 CF B1 FF FF EB 65 8B 0D ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? E8 0F FA FF FF 3B 05 ?? ?? ?? ?? 75 0D A1 ?? ?? ?? ?? 8B 40 3C E8 6E FB FF FF 6A 03 E8 07 C4 FF FF A1 ?? ?? ?? ?? E8 C1 C6 FF FF 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? A1 ?? ?? ?? ?? E8 AA C6 FF FF A1 ?? ?? ?? ?? E8 A0 C6 FF FF C3 E9 AE B0 FF FF EB E4 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 F0 E8 A7 B5 FF FF C3 E9 91 B0 FF FF EB F0 E8 62 B4 FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule KenPack_V0_2____CHKen_Com_____Sign_By_fly___20080319
{
strings:
		$a0 = { 6A 18 E8 14 00 00 00 58 8D 4A 18 51 8D 92 ?? ?? ?? ?? 64 8B 08 FF 31 89 21 89 10 5A FF E2 72 8B 44 24 0C 8B ?? A8 00 00 00 8D 8A ?? ?? ?? ?? 60  }

condition:
		$a0 at entrypoint
}
	
	
rule Patch_Creation_Wizard_v1_2_Byte_Patch
{
strings:
		$a0 = { E8 7F 03 00 00 6A 00 E8 24 03 00 00 A3 B8 33 40 00 6A 00 68 29 10 40 00 6A 00 6A 01 50 E8 2C 03 00 00 6A 00 E8 EF 02 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C1 00 00 00 6A 01 FF 35 B8 33 40 00 E8 1B 03 00 00 50 6A 01 68 80 00 00 00 FF 75 08 E8 1D 03 00 00 68 5F 30 40 00 6A 65 FF 75 08 E8 14 03 00 00 68 B0 30 40 00 6A 67 FF 75 08 E8 05 03 00 00 68 01 31 40 00 6A 66 FF 75 08 E8 F6 02 00 00 6A 00 FF 75 08 E8 C8 02 00 00 A3 B4 33 40 00 C7 05 BC 33 40 00 2C 00 00 00 C7 05 C0 33 40 00 10 00 00 00 C7 05 C4 33 40 00 00 08 00 00 68 BC 33 40 00 6A 01 6A FF FF 35 B4 33 40 00 E8 97 02 00 00 C7 05 C4 33 40 00 00 00 00 00 C7 05 E0 33 40 00 00 30 40 00 C7 05 E4 33 40 00 01 00 00 00 68 BC 33 40 00 6A 01 6A FF FF 35 B4 33 40 00 E8 65 02 00 00 EB 5F EB 54  }

condition:
		$a0 at entrypoint
}
	
	
rule PC_Guard_for_Win32_v5_00____SofPro_Blagoje_Ceklic
{
strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 ?? ?? ?? 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C  }

condition:
		$a0 at entrypoint
}
	
	
rule modified_HACKSTOP_v1_11f
{
strings:
		$a0 = { 52 B4 30 CD 21 52 FA ?? FB 3D ?? ?? EB ?? CD 20 0E 1F B4 09 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule Free_Pascal_v1_0_10__win32_console_
{
strings:
		$a0 = { C6 05 ?? ?? ?? 00 01 E8 ?? ?? 00 00 C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5 ?? EC  }

condition:
		$a0 at entrypoint
}
	
	
rule eXPressor_PacK_V1_5_0_X____CGSoftLabs_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 83 A5 ?? ?? ?? ?? ?? F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 2E 00 83 7D 0C ?? 75 23 8B 45 08 A3 ?? ?? ?? ?? 6A 04 68 00 10 00 00 68 20 03 00 00 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB 04  }

condition:
		$a0 at entrypoint
}
	
	
rule N_Joy_1_1____NEX
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 0C 3C 40 00 E8 24 FC FF FF 6A 00 68 28 3A 40 00 6A 0A 6A 00 E8 D8 FC FF FF E8 7F F5 FF FF 8D 40 00  }

condition:
		$a0 at entrypoint
}
	
	
rule ____Protector_v1_1_11__DDeM__PE_Engine_v0_9__DDeM__CI_v0_9_2_
{
strings:
		$a0 = { 53 51 56 E8 00 00 00 00 5B 81 EB 08 10 00 00 8D B3 34 10 00 00 B9 F3 03 00 00 BA 63 17 2A EE 31 16 83 C6 04  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v1_08_03____Alexey_Solodovnikov
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E  }

condition:
		$a0 at entrypoint
}
	
	
rule DAEMON_Protect_v0_6_7
{
strings:
		$a0 = { 60 60 9C 8C C9 32 C9 E3 0C 52 0F 01 4C 24 FE 5A 83 C2 0C 8B 1A 9D 61  }

condition:
		$a0 at entrypoint
}
	
	
rule Exe_Shield_v2_7
{
strings:
		$a0 = { EB 06 68 F4 86 06 00 C3 9C 60 E8 02 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule ExeSplitter_1_3__Split_Method_____Bill_Prisoner___TPOC
{
strings:
		$a0 = { E9 FE 01 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 73 76 63 45 72 30 31 31 2E 74 6D 70 00 00 00 00 00 00 00 00 00 64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 85 C0 0F 84 5F 02 00 00 8B 48 30 80 39 6B 74 07 80 39 4B 74 02 EB E7 80 79 0C 33 74 02 EB DF 8B 40 18 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_20__aPlib_0_43_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 92 05 00 00 EB 0C 8B 85 8E 05 00 00 89 85 92 05 00 00 8D B5 BA 05 00 00 8D 9D 41 04 00 00 33 FF E8 38 01 00 00 EB 1B 8B 85 92 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 9E 05 00 00 00 74 0E 83 BD A2 05 00 00 00 74 05 E8 D6 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 27 05 00 00 89 85 B6 05 00 00 5B FF B5 B6 05 00 00 56 FF D3 83 C4 08 8B B5 B6 05 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 92 05 00 00 83 C0 04 89 85 B2 05 00 00 EB 6E 56 FF 95 1F 05 00 00 0B C0 75 05 E8 C9 02 00 00 85 C0 0F 84 94 00 00 00 89 85 AE 05 00 00 8B C6 EB 2A 8B 85 B2 05 00 00 8B 00 50 FF B5 AE 05 00 00 E8 11 02 00 00 85 C0 74 72 89 07 83 85 B2 05 00 00 04 83 C7 04 8B 85 B2 05 00 00 83 38 00 75 D1 EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD 92 05 00 00 83 C0 04 89 85 B2 05 00 00 80 3E 01 75 8D 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 B6 05 00 00 FF 95 2B 05 00 00 68 00 80 00 00 6A 00 FF B5 B6 05 00 00 FF 95 2B 05 00 00 E8 61 00 00 00 E8 5C 01 00 00 61 E9 ?? ?? ?? ?? 61 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule SoftDefender_v1_12__Unregistered_
{
strings:
		$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 E6 01 00 00 03 C8 74 BD 75 BB E8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Exe_Shield_v2_9
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0B 20 40 00 B9 EB 08 00 00 8D BD 53 20 40 00 8B F7 AC ?? ?? ?? F8  }

condition:
		$a0 at entrypoint
}
	
	
rule EncryptPE_V2_2006_7_10_V2_2006_10_25____WFS_____Sign_By_fly
{
strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule KGCrypt_vx_x
{
strings:
		$a0 = { E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 64 A1 30 ?? ?? ?? 84 C0 74 ?? 64 A1 20 ?? ?? ?? 0B C0 74  }

condition:
		$a0 at entrypoint
}
	
	
rule Free_Pascal_v1_06
{
strings:
		$a0 = { C6 05 ?? ?? 40 00 ?? E8 ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Armadillo_V5_00_V5_X_Dll____Silicon_Realms_Toolworks_____Sign_By_fly
{
strings:
		$a0 = { 83 7C 24 08 01 75 05 E8 ?? ?? ?? ?? FF 74 24 04 8B 4C 24 10 8B 54 24 0C E8 ?? ?? ?? ?? 59 C2 0C 00 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 ?? ?? ?? ?? C7 00 0C 00 00 00 57 57 57 57 57 E8 ?? ?? ?? ?? 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 ?? ?? ?? ?? 59 89 7D FC FF 75 08 E8 ?? ?? ?? ?? 59 89 45 E4 C7 45 FC FE FF FF FF E8 ?? ?? ?? ?? 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 ?? ?? ?? ?? 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 ?? ?? ?? ?? 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 ?? ?? ?? ?? 59 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule vfp_exeNc_v6_00____Wang_JianGuo
{
strings:
		$a0 = { 60 E8 01 00 00 00 63 58 E8 01 00 00 00 7A 58 2D 0D 10 40 00 8D 90 C1 10 40 00 52 50 8D 80 49 10 40 00 5D 50 8D 85 65 10 40 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC  }

condition:
		$a0 at entrypoint
}
	
	
rule EZIP_v1_0
{
strings:
		$a0 = { E9 19 32 00 00 E9 7C 2A 00 00 E9 19 24 00 00 E9 FF 23 00 00 E9 1E 2E 00 00 E9 88 2E 00 00 E9 2C  }

condition:
		$a0 at entrypoint
}
	
	
rule DJoin_v0_7_public__xor_encryption_____drmist
{
strings:
		$a0 = { C6 05 ?? ?? 40 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule kkrunchy_0_23_alpha_2____Ryd
{
strings:
		$a0 = { BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? 00 B8 ?? ?? ?? 00 89 45 04 89 45 54 50 C7 45 10 ?? ?? ?? 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF ?? ?? ?? 01 31 C9 41 8D 74 09 01 B8 CA 8E 2A 2E 99 F7 F6 01 C3 89 D8 C1 E8 15 AB FE C1 75 E8 BE  }

condition:
		$a0 at entrypoint
}
	
	
rule PE_Protector_V2_60__hying_s_PE_Armor_V0_460_modify______Engprog_____Sign_By_fly
{
strings:
		$a0 = { 55 53 51 52 56 57 E8 E1 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5D 81 ED 0B 00 00 00 8B 9D 9B 00 00 00 03 9D 9F 00 00 00 0B DB 74 14 8B 83 7F 46 00 00 03 83 87 46 00 00 5F 5E 5A 59 5B 5D FF E0 8D 75 43 56 FF 55 54 8D B5 A3 00 00 00 56 50 FF 55 50 89 85 B0 00 00 00 8D 75 43 56 FF 55 54 8D B5 B4 00 00 00 56 50 FF 55 50 89 85 C0 00 00 00 8D 75 43 56 FF 55 54 8D B5 C4 00 00 00 56 50 FF 55 50 89 85 D0 00 00 00 6A 40 68 00 10 00 00 FF B5 97 00 00 00 6A 00 FF 95 B0 00 00 00 89 85 9B 00 00 00 55 8D 9D F2 01 00 00 53 8D 9D CC 01 00 00 FF D3 8B 74 24 04 8B 7C 24 0C F7 46 04 07 00 00 00 75 08 81 3E 27 00 00 C0 75 06 B8 00 00 00 00 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule SmokesCrypt_v1_2
{
strings:
		$a0 = { 60 B8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1  }

condition:
		$a0 at entrypoint
}
	
	
rule yoda_s_Protector_V1_0b____Ashkbiz_Danehkar_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 ?? E8 03 00 00 00 EB 01 ?? AC  }

condition:
		$a0 at entrypoint
}
	
	
rule PC_Shrinker_v0_71
{
strings:
		$a0 = { 9C 60 BD ?? ?? ?? ?? 01 AD 54 3A 40 ?? FF B5 50 3A 40 ?? 6A 40 FF 95 88 3A 40 ?? 50 50 2D ?? ?? ?? ?? 89 85  }

condition:
		$a0 at entrypoint
}
	
	
rule Upack_v0_29_beta____Dwing
{
strings:
		$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 29  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Embedded_V2_2X_V2_308____Jitit_____Sign_By_fly
{
strings:
		$a0 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 B9 FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_v0_89_6___v1_02___v1_05__v1_22__Delphi__stub
{
strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF EB 0E ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_V1_18__aPlib_0_43_____ap0x_____Sign_By_fly
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule UPX_Modified_stub
{
strings:
		$a0 = { 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? 00 00 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? 00 00 61 E9 ?? ?? ?? FF  }

condition:
		$a0 at entrypoint
}
	
	
rule MicroDog_Win32Shell_V4_0_9_3_Dll____SafeNet_____Sign_By_fly
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 19 FF FF FF E9 AF EC FF FF 90 90 90 90 90 55 8B EC 83 EC 18 53 56 57 8B 45 08 8B 00 C1 E8 10 89 45 FC 8B 45 08 8B 00 25 FF FF 00 00 89 45 F8 C7 45 F4 5A 01 00 00 C7 45 EC 35 4E 00 00 8B 45 F4 0F AF 45 F8 25 FF FF 00 00 89 45 F0 83 7D FC 00 74 0F 8B 45 EC 0F AF 45 FC 25 FF FF 00 00 01 45 F0 8B 45 EC 0F AF 45 F8 8B 4D F0 C1 E1 10 81 E1 00 00 FF FF 03 C1 40 89 45 E8 8B 45 E8 8B 4D 08 89 01 C1 6D E8 10 81 65 E8 FF 7F 00 00 66 8B 45 E8 EB 00 5F 5E 5B C9 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_Full_Edition_1_17_DLL____Ap0x
{
strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8  }

condition:
		$a0 at entrypoint
}
	
	
rule RPolyCrypt_v_1_0__personal_polycryptor__sign_from_pinch
{
strings:
		$a0 = { 50 58 97 97 60 61 8B 04 24 80 78 F3 6A E8 00 00 00 00 58 E8 00 00 00 00 58 91 91 EB 00 0F 85 6B F4 76 6F E8 00 00 00 00 83 C4 04 E8 00 00 00 00 58 90 E8 00 00 00 00 83 C4 04 8B 04 24 80 78 F1  }

condition:
		$a0 at entrypoint
}
	
	
rule CodeCrypt_v0_164
{
strings:
		$a0 = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F EB 03 FF 1D 34  }

condition:
		$a0 at entrypoint
}
	
	
rule Borland_Delphi_v4_0___v5_0
{
strings:
		$a0 = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 ?? ?? ?? ?? C7 42 0C ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3  }
	$a1 = { 55 8B EC 83 C4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20  }
	$a2 = { 50 6A 00 E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 00 00 00 00 C7 42 0C 00 00 00 00 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule EXECrypt_1_0____ReBirth
{
strings:
		$a0 = { 90 90 60 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 96 0C 00 00 90 8D BD 4E 28 40 00 8B F7 AC  }

condition:
		$a0 at entrypoint
}
	
	
rule ASPack_v1_00b
{
strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44  }

condition:
		$a0 at entrypoint
}
	
	
rule Safedisc_V4_50_000____Macrovision_Corporation____Sign_By_fly___20080117
{
strings:
		$a0 = { 55 8B EC 60 BB 6E ?? ?? ?? B8 0D ?? ?? ?? 33 C9 8A 08 85 C9 74 0C B8 E4 ?? ?? ?? 2B C3 83 E8 05 EB 0E 51 B9 2B ?? ?? ?? 8B C1 2B C3 03 41 01 59 C6 03 E9 89 43 01 51 68 D9 ?? ?? ?? 33 C0 85 C9 74 05 8B 45 08 EB 00 50 E8 25 FC FF FF 83 C4 08 59 83 F8 00 74 1C C6 03 C2 C6 43 01 0C 85 C9 74 09 61 5D B8 00 00 00 00 EB 96 50 B8 F9 ?? ?? ?? FF 10 61 5D EB 47 80 7C 24 08 00 75 40 51 8B 4C 24 04 89 0D ?? ?? ?? ?? B9 02 ?? ?? ?? 89 4C 24 04 59 EB 29 50 B8 FD ?? ?? ?? FF 70 08 8B 40 0C FF D0 B8 FD ?? ?? ?? FF 30 8B 40 04 FF D0 58 B8 25 ?? ?? ?? FF 30 C3 72 16 61 13 60 0D E9 ?? ?? ?? ?? 66 83 3D ?? ?? ?? ?? ?? 74 05 E9 91 FE FF FF C3  }

condition:
		$a0 at entrypoint
}
	
	
rule RLPack_____Ap0x
{
strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 2C 0A 00 00 8D 9D 22 02 00 00 33 FF E8 83 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 CD 09 00 00 89 85 14 0A 00 00 EB 14 60 FF B5 14 0A  }
	$a1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 83 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 EB 09 00 00 89 85 3A 0A 00 00 EB 14 60 FF B5 3A 0A  }
	$a2 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 0C 00 00 EB 03 0C 00 00 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 47 02 00 00 EB 03 15 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 9B 0A  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint
}
	
	
rule tElock_v0_41x
{
strings:
		$a0 = { 66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 50 8B FE 68 78 01 ?? ?? 59 EB 01 EB AC 54 E8 03 ?? ?? ?? 5C EB 08  }

condition:
		$a0 at entrypoint
}
	
	
rule nPack_V1_1_300_2006_Beta____NEOx_____Sign_By_fly
{
strings:
		$a0 = { 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8 2D 02 00 00 E8 DD 06 00 00 E8 2C 06 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 56 57 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B F8 68 ?? ?? ?? ?? 57 FF D6 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 5F A3 ?? ?? ?? ?? 5E C3  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0_
{
strings:
		$a0 = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE  }
	$a1 = { 91 EB 02 CD 20 BF 50 BC 04 6F 91 BE D0 ?? ?? 6F EB 02 CD 20 2B F7 EB 02 F0 46 8D 1D F4 00  }
	$a2 = { C1 CE 10 C1 F6 0F 68 00 ?? ?? 00 2B FA 5B 23 F9 8D 15 80 ?? ?? 00 E8 01 00 00 00 B6 5E 0B  }
	$a3 = { D1 E9 03 C0 68 80 ?? ?? 00 EB 02 CD 20 5E 40 BB F4 00 00 00 33 CA 2B C7 0F B6 16 EB 01 3E  }
	$a4 = { E8 01 00 00 00 0E 59 E8 01 00 00 00 58 58 BE 80 ?? ?? 00 EB 02 61 E9 68 F4 00 00 00 C1 C8  }
	$a5 = { EB 01 4D 83 F6 4C 68 80 ?? ?? 00 EB 02 CD 20 5B EB 01 23 68 48 1C 2B 3A E8 02 00 00 00 38  }
	$a6 = { EB 02 AB 35 EB 02 B5 C6 8D 05 80 ?? ?? 00 C1 C2 11 BE F4 00 00 00 F7 DB F7 DB 0F BE 38 E8  }
	$a7 = { EB 02 CD 20 ?? CF ?? ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00  }
	$a8 = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? ?? BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68  }

condition:
		$a0 at entrypoint or $a1 at entrypoint or $a2 at entrypoint or $a3 at entrypoint or $a4 at entrypoint or $a5 at entrypoint or $a6 at entrypoint or $a7 at entrypoint or $a8 at entrypoint
}
	
	
rule Launcher_Generator_v1_03
{
strings:
		$a0 = { 68 00 20 40 00 68 10 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 68 F0 22 40 00 6A 00 E8 93 00 00 00 85 C0 0F 84 7E 00 00 00 B8 00 00 00 00 3B 05 68 20 40 00 74 13 6A ?? 68 60 23 40 00 68 20 23 40 00 6A 00 E8 83 00 00 00 A1 58 20 40 00 3B 05 6C 20 40 00 74 51 C1 E0 02 A3 5C 20 40 00 BB 70 21 40 00 03 C3 8B 18 68 60 20 40 00 53 B8 F0 21 40 00 03 05 5C 20 40 00 8B D8 8B 03 05 70 20 40 00 50 B8 70 22 40 00 03 05 5C 20 40 00 FF 30 FF 35 00 20 40 00 E8 26 00 00 00 A1 58 20 40 00 40 A3 58 20 40 00 EB A2 6A FF E8 00 00 00 00 FF 25 5C 30 40 00 FF 25 60 30 40 00 FF 25 64 30 40 00 FF 25 68 30 40 00 FF 25 6C 30 40 00 FF 25 74 30 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule NsPacK_V3_3____LiuXingPing_____Sign_By_fly
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 00 74  }

condition:
		$a0 at entrypoint
}
	
	
rule NsPack_3_0____North_Star
{
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 00 74 15 8B F5 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36  }

condition:
		$a0 at entrypoint
}
	
	
rule DIET_v1_44__v1_45f
{
strings:
		$a0 = { F8 9C 06 1E 57 56 52 51 53 50 0E FC 8C C8 BA ?? ?? 03 D0 52  }

condition:
		$a0 at entrypoint
}
	
	
rule Pack_Master_v1_0
{
strings:
		$a0 = { 60 E8 01 ?? ?? ?? E8 83 C4 04 E8 01 ?? ?? ?? E9 5D 81 ED D3 22 40 ?? E8 04 02 ?? ?? E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46  }
	$a1 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED D3 22 40 00 E8 04 02 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule Vx__XRCV_1015
{
strings:
		$a0 = { E8 ?? ?? 5E 83 ?? ?? 53 51 1E 06 B4 99 CD 21 80 FC 21 ?? ?? ?? ?? ?? 33 C0 50 8C D8 48 8E C0 1F A1 ?? ?? 8B  }

condition:
		$a0 at entrypoint
}
	
	
rule PGMPACK_v0_14
{
strings:
		$a0 = { 1E 17 50 B4 30 CD 21 3C 02 73 ?? B4 4C CD 21 FC BE ?? ?? BF ?? ?? E8 ?? ?? E8 ?? ?? BB ?? ?? BA ?? ?? 8A C3 8B F3  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake__BJFNT_1_3_____emadicius
{
strings:
		$a0 = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 EB 02 C7 05 EB 02 CD 20 E8 03 00 00 00 E9 EB 04 58 40 50 C3 61 9D 1F EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule CPAV
{
strings:
		$a0 = { E8 ?? ?? 4D 5A B1 01 93 01 00 00 02  }

condition:
		$a0 at entrypoint
}
	
	
rule PGMPACK_v0_13
{
strings:
		$a0 = { FA 1E 17 50 B4 30 CD 21 3C 02 73 ?? B4 4C CD 21 FC BE ?? ?? BF ?? ?? E8 ?? ?? E8 ?? ?? BB ?? ?? BA ?? ?? 8A C3 8B F3  }

condition:
		$a0 at entrypoint
}
	
	
rule Sc_Obfuscator____SuperCRacker_____Sign_By_fly
{
strings:
		$a0 = { 60 33 C9 8B 1D ?? ?? ?? ?? 03 1D ?? ?? ?? ?? 8A 04 19 84 C0 74 09 3C ?? 74 05 34 ?? 88 04 19 41 3B 0D ?? ?? ?? ?? 75 E7 A1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 61 FF 25 ?? ?? ?? ?? 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__CIH_Version_1_2_TTIT____WIN95CIH___
{
strings:
		$a0 = { 55 8D ?? ?? ?? 33 DB 64 87 03 E8 ?? ?? ?? ?? 5B 8D  }

condition:
		$a0 at entrypoint
}
	
	
rule HACKSTOP_v1_00
{
strings:
		$a0 = { FA BD ?? ?? FF E5 6A 49 48 0C ?? E4 ?? 3F 98 3F  }

condition:
		$a0 at entrypoint
}
	
	
rule ProActivate_V1_0X____TurboPower_Software_Company_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC B9 0E 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? ?? ?? ?? 90 90 90 90 90 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 A1 ?? ?? ?? ?? 83 C0 05 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0D 00 00 00 E8 85 E2 FF FF 81 3D ?? ?? ?? ?? 21 7E 7E 40 75 7A 81 3D ?? ?? ?? ?? 43 52 43 33 75 6E 81 3D ?? ?? ?? ?? 32 40 7E 7E 75 62 81 3D ?? ?? ?? ?? 21 7E 7E 40 75 56 81 3D ?? ?? ?? ?? 43 52 43 33 75 4A 81 3D ?? ?? ?? ?? 32 40 7E 7E 75 3E 81 3D ?? ?? ?? ?? 21 7E 7E 40 75 32 81 3D ?? ?? ?? ?? 43 52 43 33  }

condition:
		$a0 at entrypoint
}
	
	
rule Nullsoft_Install_System_v2_0b2__v2_0b3
{
strings:
		$a0 = { 83 EC 0C 53 55 56 57 FF 15 ?? 70 40 00 8B 35 ?? 92 40 00 05 E8 03 00 00 89 44 24 14 B3 20 FF 15 2C 70 40 00 BF 00 04 00 00 68 ?? ?? ?? 00 57 FF 15 ?? ?? 40 00 57 FF 15  }

condition:
		$a0 at entrypoint
}
	
	
rule Hardlock_dongle__Alladin_
{
strings:
		$a0 = { 5C 5C 2E 5C 48 41 52 44 4C 4F 43 4B 2E 56 58 44 00 00 00 00 5C 5C 2E 5C 46 45 6E 74 65 44 65 76  }

condition:
		$a0 at entrypoint
}
	
	
rule FSG_v1_10__Eng_____dulek_xt_____MASM32___TASM32_
{
strings:
		$a0 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB  }

condition:
		$a0 at entrypoint
}
	
	
rule Morphine_v1_2
{
strings:
		$a0 = { 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? 00 00 00 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 51 66 ?? ?? ?? 59 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E2 ?? ?? ?? ?? ?? 82 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Werus_Crypter_1_0___by_Kas
{
strings:
		$a0 = { BB E8 12 40 00 80 33 05 E9 7D FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_PE_Crypt_1_02_____emadicius
{
strings:
		$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 05 50 E8 08 00 00 00 EA FF 58 EB 18 EB 01 0F EB 02 CD 20 EB 03 EA CD 20 58 58 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule DotFix_NiceProtect_vna
{
strings:
		$a0 = { 60 E8 55 00 00 00 8D BD 00 10 40 00 68 ?? ?? ?? 00 03 3C 24 8B F7 90 68 31 10 40 00 9B DB E3 55 DB 04 24 8B C7 DB 44 24 04 DE C1 DB 1C 24 8B 1C 24 66 AD 51 DB 04 24 90 90 DA 8D 77 10 40 00 DB 1C 24 D1 E1 29  }

condition:
		$a0 at entrypoint
}
	
	
rule SLVc0deProtector_1_1x____SLV___ICU
{
strings:
		$a0 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C ?? ?? 00  }

condition:
		$a0 at entrypoint
}
	
	
rule aPack_v0_62
{
strings:
		$a0 = { 1E 06 8C C8 8E D8 ?? ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B6  }

condition:
		$a0 at entrypoint
}
	
	
rule CrypKey_V5_6_X____Kenonic_Controls_Ltd______Sign_By_fly
{
strings:
		$a0 = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 00 75 07 6A 00 E8  }

condition:
		$a0 at entrypoint
}
	
	
rule LameCrypt____LaZaRus
{
strings:
		$a0 = { 60 66 9C BB 00 ?? ?? 00 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 B8 ?? ?? 40 00 FF E0  }

condition:
		$a0 at entrypoint
}
	
	
rule EncryptPE_V1_2003_3_18_V1_2003_5_18____WFS_____Sign_By_fly
{
strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule __PseudoSigner_0_1_rule__PE_Intro_1_0______Anorganix
{
strings:
		$a0 = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A E9  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a____emadicius
{
strings:
		$a0 = { E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF FF FF 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C  }

condition:
		$a0 at entrypoint
}
	
	
rule y0da_s_Crypter_v1_0
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED E7 1A 40 00 E8 A1 00 00 00 E8 D1 00 00 00 E8 85 01 00 00 F7 85  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_1_2_5_8____Obsidium_Software
{
strings:
		$a0 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 7B 21 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule StarForce_V1_X_V5_X____StarForce_Copy_Protection_System_____Sign_By_fly___20090906
{
strings:
		$a0 = { 68 ?? ?? ?? ?? ?? 25 ?? ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule GHF_Protector__pack_only______GPcH
{
strings:
		$a0 = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 00 00 00 00 6A 40 FF D0 89 05 ?? ?? ?? ?? 89 C7 BE ?? ?? ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 61 B9 FC FF FF FF 8B 1C 08 89 99 ?? ?? ?? ?? E2 F5 90 90 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 01 D6 8B 46 0C 85 C0 0F 84 87 00 00 00 01 D0 89 C3 50 B8 ?? ?? ?? ?? FF 10 85 C0 75 08 53 B8 ?? ?? ?? ?? FF 10 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 BA ?? ?? ?? ?? 8B 06 85 C0 75 03 8B 46 10 01 D0 03 05 ?? ?? ?? ?? 8B 18 8B 7E 10 01 D7 03 3D ?? ?? ?? ?? 85 DB 74 2B F7 C3 00 00 00 80 75 04 01 D3 43 43 81 E3 FF FF FF 0F 53 FF 35 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 89 07 83 05 ?? ?? ?? ?? 04 EB AE 83 C6 14 BA ?? ?? ?? ?? E9 6E FF FF FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 8B 15 ?? ?? ?? ?? 52 FF D0 61 BA ?? ?? ?? ?? FF E2 90 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule KByS_V0_22____shoooo_____Sign_By_fly
{
strings:
		$a0 = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 11 55 07 8B EC B8 ?? ?? ?? ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule rule__MSLRH__v0_32a__fake_yoda_s_cryptor_1_2_____emadicius
{
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC 90 2C 8A C0 C0 78 90 04 62 EB 01 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF  }

condition:
		$a0 at entrypoint
}
	
	
rule ACProtect_v1_32
{
strings:
		$a0 = { 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E9  }

condition:
		$a0 at entrypoint
}
	
	
rule SimbiOZ_1_3____Extranger
{
strings:
		$a0 = { 57 57 8D 7C 24 04 50 B8 00 ?? ?? ?? AB 58 5F C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Thinstall_Embedded_V2_521____Jitit_____Sign_By_fly
{
strings:
		$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D A7 1A 00 00 B9 6C 1A 00 00 BA 20 1B 00 00 BE 00 10 00 00 BF B0 53 00 00 BD EC 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? 81 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10  }

condition:
		$a0 at entrypoint
}
	
	
rule Stone_s_PE_Encryptor_v2_0
{
strings:
		$a0 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 42 30 40 ?? FF 95 32 35 40 ?? B8 37 30 40 ?? 03 C5 2B 85 1B 34 40 ?? 89 85 27 34 40 ?? 83  }

condition:
		$a0 at entrypoint
}
	
	
rule Obsidium_V1_3_3_7__2007_06_23_____Obsidium_Software_____Sign_By_fly
{
strings:
		$a0 = { EB 02 ?? ?? E8 27 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 23 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8 F7 26 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_v0_4x___v0_5x
{
strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 ?? 8B FE 68 79 01 ?? ?? 59 EB 01  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__VCL__encrypted_
{
strings:
		$a0 = { 01 B9 ?? ?? 81 34 ?? ?? 46 46 E2 F8 C3  }
	$a1 = { 01 B9 ?? ?? 81 35 ?? ?? 47 47 E2 F8 C3  }

condition:
		$a0 at entrypoint or $a1 at entrypoint
}
	
	
rule CrypKey_V6_1X_DLL____CrypKey__Canada__Inc______Sign_By_fly
{
strings:
		$a0 = { 83 3D ?? ?? ?? ?? 00 75 34 68 ?? ?? ?? ?? E8  }

condition:
		$a0 at entrypoint
}
	
	
rule EXE_Packer_v7_0_by_TurboPower_Software
{
strings:
		$a0 = { 1E 06 8C C3 83 ?? ?? 2E ?? ?? ?? ?? B9 ?? ?? 8C C8 8E D8 8B F1 4E 8B FE  }

condition:
		$a0 at entrypoint
}
	
	
rule yzpack_V1_12____UsAr_____Sign_By_fly
{
strings:
		$a0 = { 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 ?? ?? ?? ?? B4 09 BA 00 00 1F CD 21 B8 01 4C CD 21 40 00 00 00 50 45 00 00 4C 01 02 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 E0 00 ?? ?? 0B 01 ?? ?? ?? ?? 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule FreeJoiner_1_5_1____GlOFF
{
strings:
		$a0 = { 90 87 FF 90 90 B9 2B 00 00 00 BA 07 10 40 00 83 C2 03 90 87 FF 90 90 B9 04 00 00 00 90 87 FF 90 33 C9 C7 05 09 30 40 00 00 00 00 00 68 00 01 00 00 68 21 30 40 00 6A 00 E8 B7 02 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 68 21 30 40 00 E8 8F 02 00 00 A3 19 30 40 00 90 87 FF 90 8B 15 09 30 40 00 81 C2 04 01 00 00 F7 DA 6A 02 6A 00 52  }

condition:
		$a0 at entrypoint
}
	
	
rule hmimys_Protect_v1_0
{
strings:
		$a0 = { E8 BA 00 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 40 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 AD 8B DE 8B F0 83 C3 44 AD 85 C0 74 32 8B F8 56 FF 13 8B E8 AC 84 C0 75 FB AC 84 C0 74 EA 4E AD A9  }

condition:
		$a0 at entrypoint
}
	
	
rule SPEC_b3
{
strings:
		$a0 = { 5B 53 50 45 43 5D E8 ?? ?? ?? ?? 5D 8B C5 81 ED 41 24 40 ?? 2B 85 89 26 40 ?? 83 E8 0B 89 85 8D 26 40 ?? 0F B6 B5 91 26 40 ?? 8B FD  }

condition:
		$a0 at entrypoint
}
	
	
rule SPEC_b2
{
strings:
		$a0 = { 55 57 51 53 E8 ?? ?? ?? ?? 5D 8B C5 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 09 89 85 ?? ?? ?? ?? 0F B6  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__KBDflags_1024
{
strings:
		$a0 = { 8B EC 2E 89 2E 24 03 BC 00 04 8C D5 2E 89 2E 22  }

condition:
		$a0 at entrypoint
}
	
	
rule WWPACK_v3_05c4__Extractable___Password_checking_
{
strings:
		$a0 = { 03 05 80 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3  }

condition:
		$a0 at entrypoint
}
	
	
rule AHTeam_EP_Protector_0_3__fake_PE_Lock_NT_2_04_____FEUERRADER
{
strings:
		$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB  }

condition:
		$a0 at entrypoint
}
	
	
rule tElock_0_98____tE_
{
strings:
		$a0 = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? 1E ?? ?? 00 00 00 00 00 00 00 00 00 3E ?? ?? 00 2E ?? ?? 00 26 ?? ?? 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 36 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 56 ?? ?? 00 00 00 00 00 69 ?? ?? 00 00 00 00 00 56 ?? ?? 00 00 00 00 00 69 ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65  }

condition:
		$a0 at entrypoint
}
	
	
rule ANDpakk2_0_18___by_Dmitry__AND__Andreev
{
strings:
		$a0 = { FC BE D4 00 40 00 BF 00 ?? ?? 00 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 4D D1 F8 8B E8 EB 09 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 13 C9 75 1A 41 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 73 EA 83 C1 02 81 FD 00 FB FF FF 83 D1 01 56 8D 34 2F F3 A4 5E E9 73 FF FF FF C3  }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin_V0_b____cyberbob_____Sign_By_fly___20080312
{
strings:
		$a0 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 72 C8 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 26 E8 01 00 00 00 ?? 5A 33 C9 ?? ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B ?? ?? ?? ?? ?? ?? 8B 59 24 03 DA 8B 1B ?? ?? ?? ?? ?? ?? 53 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6A 0C 5B 6A 17 59 30 0C 03 02 CB 4B 75 F8 40 8D 9D 41 8F 4E 00 50 53 81 2C 24 01 78 0E 00 ?? ?? ?? ?? ?? ?? C3 92 EB 15 68 ?? ?? ?? ?? ?? B9 ?? 08 00 00 ?? ?? ?? ?? ?? ?? 4F 30 1C 39 FE CB E2 F9 68 1D 01 00 00 59 ?? ?? ?? ?? ?? ?? C0 0C 39 02 E2 FA 68 ?? ?? ?? ?? 50 01 6C 24 04 E8 BD 09 00 00 33 C0 0F 84 C0 08 00 00 ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF E0 C3 8D 64 24 04 E8 53 0A 00 00 D7 58 5B 51 C3 F7 F3 32 DA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 2C 24 A3 00 00 00 58 ?? ?? ?? ?? ?? ?? 53 FF E0  }

condition:
		$a0 at entrypoint
}
	
	
rule Fly_Crypter_1_0____ut1lz
{
strings:
		$a0 = { 55 8B EC 83 C4 F0 53 B8 18 22 44 44 E8 7F F7 FF FF E8 0A F1 FF FF B8 09 00 00 00 E8 5C F1 FF FF 8B D8 85 DB 75 05 E8 85 FD FF FF 83 FB 01 75 05 E8 7B FD FF FF 83 FB 02 75 05 E8 D1 FD FF FF 83 FB 03 75 05 E8 87 FE FF FF 83 FB 04 75 05 E8 5D FD FF FF 83 FB 05 75 05 E8 B3 FD FF FF 83 FB 06 75 05 E8 69 FE FF FF 83 FB 07 75 05 E8 5F FE FF FF 83 FB 08 75 05 E8 95 FD FF FF 83 FB 09 75 05 E8 4B FE FF FF 5B E8 9D F2 FF FF 90  }

condition:
		$a0 at entrypoint
}
	
	
rule Sentinel_UltraPro_Dongle_V1_1_0_____SafeNet_Inc______Sign_By_fly
{
strings:
		$a0 = { A1 ?? ?? ?? ?? 85 C0 0F 85 59 06 00 00 55 56 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 25 FE ?? ?? ?? 0D 01 ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 50 C7 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 BD 0F 00 00 83 C4 04 83 F8 64 7C E7 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 A1 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 66 8B 4D 00 83 C5 08 ?? ?? ?? ?? ?? ?? ?? 66 8B 75 FA ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 8B 55 FC 81 E1 FF FF 00 00 81 F9  }

condition:
		$a0 at entrypoint
}
	
	
rule LOCK98_V1_00_28____keenvim
{
strings:
		$a0 = { 55 E8 00 00 00 00 5D 81 ?? ?? ?? ?? ?? EB 05 E9 ?? ?? ?? ?? EB 08  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Eddie_1800
{
strings:
		$a0 = { E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E 8B FE 33 C0 50 8E D8 C4 ?? ?? ?? 2E ?? ?? ?? ?? 2E  }

condition:
		$a0 at entrypoint
}
	
	
rule W32_Jeefo__PE_File_Infector_
{
strings:
		$a0 = { 55 89 E5 83 EC 08 83 C4 F4 6A 02 A1 C8 ?? ?? ?? FF D0 E8 ?? ?? ?? ?? C9 C3  }

condition:
		$a0 at entrypoint
}
	
	
rule Lite_0_03a_DLL
{
strings:
		$a0 = { 80 7C 24 08 01 75 F4 E9 ?? ?? FF FF 00 10 00 00 0C 00 00 00 06 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 00 ?? ?? 00 00 00 00 00 00  }

condition:
		$a0 at entrypoint
}
	
	
rule Vx__Noon_1163
{
strings:
		$a0 = { E8 ?? ?? 5B 50 56 B4 CB CD 21 3C 07 ?? ?? 81 ?? ?? ?? 2E ?? ?? 4D 5A ?? ?? BF 00 01 89 DE FC  }

condition:
		$a0 at entrypoint
}
	
	
rule PESpin_V1_0____cyberbob_____Sign_By_fly___20080312
{
strings:
		$a0 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 C8 DC 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 ?? ?? ?? ?? ?? ?? ?? C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 ?? EB FB FF 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 ?? ?? ?? ?? 83 04 24 0C C3  }

condition:
		$a0 at entrypoint
}
	
	