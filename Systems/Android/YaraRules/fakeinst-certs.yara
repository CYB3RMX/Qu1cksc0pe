import "androguard"
rule FakeInst_certs
{
	meta:
		description = "FakeInst installer from fake developers"
		sample = "acce1154630d327ca9d888e0ecf44a1370cf42b3b28a48446a9aaaec9ec789c3"
  
	condition:
		androguard.certificate.sha1("C67F8FC63E25C1F2D3D3623210D126BC96AFEE69") or
		androguard.certificate.sha1("FB2FD4D89D7363E6386C865247825C041F23CDEB") or
		androguard.certificate.sha1("9AD4DB5F64C6B12106DCAE54A9759154C56E27E1") or
		androguard.certificate.sha1("0A721AF65BBB389EA9E224A59833BD3FD92F4129") or
		androguard.certificate.sha1("5D66125A5FAE943152AE83D5787CDCFD1C579F4E")	or	
		androguard.certificate.sha1("2260A1A17C96AF2C8208F0C0A34CF3B87A28E960")
}