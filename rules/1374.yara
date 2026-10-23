rule Trojan_Win32_Socgolsh_SG_2147916318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.SG"
        threat_id = "2147916318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "schtasks /create /f /tn" wide //weight: 1
        $x_1_2 = {5c 00 70 00 79 00 74 00 68 00 6f 00 6e 00 77 00 2e 00 65 00 78 00 65 00 [0-255] 2e 00 70 00 79 00 20 00 2d 00 69 00 70 00 [0-255] 2d 00 70 00 6f 00 72 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
