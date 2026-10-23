rule Trojan_Win32_Amynex_A_2147777774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amynex.A"
        threat_id = "2147777774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amynex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "|foreach{" wide //weight: 1
        $x_1_3 = "DownloadString" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 24 00 5f 00 2f 00 [0-16] 2e 00 6a 00 73 00 70 00 3f 00 [0-16] 2a 00 24 00 65 00 6e 00 76 00 3a 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 2a 00 24 00 65 00 6e 00 76 00 3a 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
