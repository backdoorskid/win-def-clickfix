rule Trojan_Win32_SuspClickFix_Q2_2147963694_0
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
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "=mshta&set " wide //weight: 1
        $x_1_3 = "&call !" wide //weight: 1
        $x_1_4 = "&ping " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
