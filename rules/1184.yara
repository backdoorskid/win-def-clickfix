rule Trojan_Win32_Powessere_X_2147831330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.X"
        threat_id = "2147831330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-48] 6d 00 73 00 68 00 74 00 6d 00 6c 00 2c 00 23 00 31 00 33 00 35 00}  //weight: 10, accuracy: Low
        $x_10_2 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-48] 6d 00 73 00 68 00 74 00 6d 00 6c 00 2c 00 23 00 31 00 33 00 35 00}  //weight: 10, accuracy: Low
        $x_1_3 = "wscript.shell" wide //weight: 1
        $x_1_4 = ".run(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}
