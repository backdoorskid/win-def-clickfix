rule Trojan_Win32_SuspClickFix_V2_2147967489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.V2"
        threat_id = "2147967489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = " --headless" wide //weight: 1
        $x_1_3 = "curl " wide //weight: 1
        $x_1_4 = "| cmd" wide //weight: 1
        $x_1_5 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-64] 2c 00 23 00}  //weight: 1, accuracy: Low
        $x_2_6 = {70 00 75 00 73 00 68 00 64 00 5c 00 5c 00 [0-64] 26 00 63 00 6d 00 64 00 3c 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
