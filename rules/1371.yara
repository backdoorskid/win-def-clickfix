rule Trojan_Win32_Socgolsh_SD_2147909963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.SD"
        threat_id = "2147909963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 [0-48] 22 00 70 00 79 00 70 00 69 00 2d 00 70 00 79 00 22 00}  //weight: 1, accuracy: Low
        $x_1_2 = "schtasks /run /tn \"pypi-py\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}
