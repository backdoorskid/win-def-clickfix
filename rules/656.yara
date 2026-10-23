rule Trojan_Win32_Ceprolad_AA_2147806027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ceprolad.AA"
        threat_id = "2147806027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceprolad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certutil" wide //weight: 1
        $x_1_2 = "curl" wide //weight: 1
        $x_1_3 = "-urlcache" wide //weight: 1
        $x_1_4 = "-f" wide //weight: 1
        $x_1_5 = "-o" wide //weight: 1
        $x_10_6 = "http" wide //weight: 10
        $x_10_7 = "citationsherbe.at" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}
