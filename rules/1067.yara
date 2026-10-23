rule Trojan_Win32_Nibtse_A_2147734631_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nibtse.A"
        threat_id = "2147734631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nibtse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "schtasks /create /tn " wide //weight: 1
        $x_1_2 = {20 00 2f 00 74 00 72 00 20 00 6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 3a 00 29 05 05 00 2f 00 [0-32] 20 00 2f 00 73 00 63 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
