rule Trojan_Win32_SuspClickFix_Z4_2147971224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Z4"
        threat_id = "2147971224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rundll32" wide //weight: 1
        $x_1_2 = {70 00 75 00 73 00 68 00 64 00 [0-16] 20 00 5c 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_3 = "@SSL\\" wide //weight: 1
        $x_1_4 = ",#1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
