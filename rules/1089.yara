rule Trojan_Win32_Ofisus_A_2147731060_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.A"
        threat_id = "2147731060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cmd.exe" wide //weight: 1
        $x_1_2 = "& /K CD C: & PowerShell -EncodedCommand dAByAHkA" wide //weight: 1
        $x_2_3 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 4e 00 6f 00 50 00 20 00 2d 00 45 00 78 00 65 00 63 00 20 00 42 00 79 00 70 00 61 00 73 00 73 00 20 00 2d 00 45 00 43 00 20 00 4a 00 41 00 42 00 70 00 41 00 47 00 34 00 41 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}
