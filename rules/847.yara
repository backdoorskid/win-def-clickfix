rule Trojan_Win32_Goptaju_C_2147959534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Goptaju.C"
        threat_id = "2147959534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Goptaju"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "invoke-webrequest" wide //weight: 1
        $x_1_2 = "iwr" wide //weight: 1
        $x_10_3 = "-Uri" wide //weight: 10
        $x_10_4 = "-Method Put" wide //weight: 10
        $x_10_5 = {63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 90 00 02 00 30 00 2d 00 2d 00 64 00 61 00 74 00 61 00 2d 00 62 00 69 00 6e 00 61 00 72 00 79 00}  //weight: 10, accuracy: High
        $x_10_6 = "net user /domain" wide //weight: 10
        $x_10_7 = "ipconfig /all" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}
