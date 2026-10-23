rule Trojan_Win32_Powemet_J_2147730746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.J"
        threat_id = "2147730746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "113"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "\\powershell.exe" wide //weight: 100
        $x_10_2 = "$env:comspec[4,24,25]" wide //weight: 10
        $x_10_3 = "$shellid[1]+$shellid[13]+'x'" wide //weight: 10
        $x_5_4 = "23 ,5 , 119, 123 ,102" wide //weight: 5
        $x_5_5 = "41, 59 ,73 , 69 , 88," wide //weight: 5
        $x_5_6 = "bxor'0x3e')})" wide //weight: 5
        $x_5_7 = "([convert]::toint16(([string]$_) , 16) -as[char])})" wide //weight: 5
        $x_5_8 = {2d 00 73 00 70 00 6c 00 69 00 74 00 20 00 27 00 [0-3] 27 00 2d 00 73 00 70 00 6c 00 69 00 74 00 27 00 [0-3] 27 00 2d 00 73 00 70 00 6c 00 69 00 74 00 20 00 27 00 [0-3] 27 00 20 00 2d 00 73 00 70 00 6c 00 69 00 74 00}  //weight: 5, accuracy: Low
        $x_1_9 = "-nop" wide //weight: 1
        $x_1_10 = "-wind" wide //weight: 1
        $x_1_11 = "-exec byp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_5_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}
