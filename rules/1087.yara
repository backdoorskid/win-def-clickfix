rule Trojan_Win32_Ofisus_A_2147731060_2
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
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\cmd.exe" wide //weight: 1
        $x_1_2 = {2f 00 63 00 [0-16] 73 00 65 00 54 00 20 00}  //weight: 1, accuracy: Low
        $x_1_3 = {26 00 26 00 [0-16] 50 00 4f 00 77 00 45 00 72 00 53 00 68 00 65 00 4c 00 4c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2d 00 66 00 [0-8] 27 00}  //weight: 1, accuracy: Low
        $x_1_5 = ").Invoke(" wide //weight: 1
        $x_1_6 = "::fromBASe64STRInG(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}
