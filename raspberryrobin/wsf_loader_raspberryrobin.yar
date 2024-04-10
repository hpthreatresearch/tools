rule wsf_loader_raspberryrobin {

	meta:
		description = "Windows Script File downloader delivering Raspberry Robin"
		author = "HP Threat Research @HPSecurity"
		filetype = "Windows Script File"
		maltype = "Loader"
		date = "2024-04-10"
	
    strings:
        $regex_string = /var\s+\w+=\[('[a-zA-Z0-9\/\+]+',){50,}/
		$str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
		$script1 = "<script>" nocase
		$script2 = "</script>" nocase
		
		$case = "case"
		$continue = "continue"
		$while = "while"
		$switch = "switch"
		$toString = "toString"
		$sig = "** SIG **"
		$decodeURIComponent = "decodeURIComponent"
		
    condition:
        $regex_string and $str and $script1 and $script2 and #case > 500 and #continue > 500 and #while > 20 and #switch > 18 and #toString == 1 and #sig > 150 and #decodeURIComponent == 1 and filesize > 350KB
}