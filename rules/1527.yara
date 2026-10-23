rule Trojan_Win32_SuspClickFix_D_2147941555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.D"
        threat_id = "2147941555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_5_2 = "http" wide //weight: 5
        $x_1_3 = "| powershell" wide //weight: 1
        $x_1_4 = "|powershell" wide //weight: 1
        $x_1_5 = {53 00 74 00 61 00 72 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-32] 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
