rule xlcall32_icedid
{
    meta:
	description = "XLCall32 - XLL Dropper used by IcedID"
	author = "HP Threat Research @HP_Security"
	filetype = "XLL"
	maltype = "Loader"
	date = "2022-02-04"
		
    strings:
        $xlcall = "XLCall32"
        $sub_rsp = {  48 81 EC ?? ?? 00 00
                      48 8D 4C 24 20
                      41 B8 ?? ?? 00 00
                      48 8D 15 ?? ?? 00 00 }

        $mov_rax = {  48 89 05 ?? ?? 01 00
                      48 8D 54 24 20
                      48 89 05 ?? ?? 01 00
                      48 8B C8 }

        $lea_rbx = {  48 8D 98 ?? ?? 00 00
                      48 89 1D ?? ?? 01 00 }

        $lea_rcx = {  48 8D 0D ?? 3F 00 00
                      48 89 1D ?? ?? 01 00
                      48 81 C4 ?? ?? 00 00
                      5B }

        $dos_mode = { 44 4F 53 20 6D 6F 64 }

    condition:
        #dos_mode > 1 and all of them
}
