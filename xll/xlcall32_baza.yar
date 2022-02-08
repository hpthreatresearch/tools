rule xlcall32_baza
{
    meta:
	description = "XLCall32 - XLL Dropper used by BazaLoader"
	author = "HP Threat Research @HP_Security"
	filetype = "XLL"
	maltype = "Loader"
	date = "2022-02-03"
	
    strings:
	$xlcall = "XLCall32"
	$mzheader1 = { 	C6 44 24 ?? 4D 
			C6 44 24 ?? 5A 
			C6 44 24 ?? 90 
			C6 44 24 ?? 00 }

	$mzheader2 = { 	C6 84 24 ?? 00 00 00 4D
			C6 84 24 ?? 00 00 00 5A
			C6 84 24 ?? 00 00 00 90
			C6 84 24 ?? 00 00 00 00 }

	$dosmode1 = { 	C6 44 24 ?? 44
			C6 44 24 ?? 4f
			C6 44 24 ?? 53
			C6 44 24 ?? 20
			C6 44 24 ?? 6d
			C6 44 24 ?? 6f
			C6 44 24 ?? 64
			C6 44 24 ?? 65 }

	$dosmode2 = { 	C6 84 24 ?? 00 00 00 44
			C6 84 24 ?? 00 00 00 4f
			C6 84 24 ?? 00 00 00 53
			C6 84 24 ?? 00 00 00 20
			C6 84 24 ?? 00 00 00 6d
			C6 84 24 ?? 00 00 00 6f
			C6 84 24 ?? 00 00 00 64
			C6 84 24 ?? 00 00 00 65 }

    condition:
	any of ($mzheader*) and any of ($dosmode*) and $xlcall
}
