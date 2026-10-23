rule Trojan_Win32_Renimoren_B_2147808364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Renimoren.B"
        threat_id = "2147808364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Renimoren"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "152"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_50_2 = "http://lurchmath.org/wordpress-temp/wp-content/plugins/" wide //weight: 50
        $x_50_3 = "/plugins/mine.bat" wide //weight: 50
        $x_1_4 = ".downloadfile(" wide //weight: 1
        $x_1_5 = ".downloadstring(" wide //weight: 1
        $x_1_6 = "GetTempFileName" wide //weight: 1
        $x_1_7 = "System.Net.WebClient" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}
