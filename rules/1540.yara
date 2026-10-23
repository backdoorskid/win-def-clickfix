rule Trojan_Win32_SuspClickFix_Q2_2147963694_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Q2"
        threat_id = "2147963694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = " /c start /min " wide //weight: 1
        $x_3_3 = "curl " wide //weight: 3
        $x_1_4 = " do call %" wide //weight: 1
        $x_1_5 = " /v:on /c set " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}
