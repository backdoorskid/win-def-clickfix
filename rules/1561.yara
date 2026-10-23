rule Trojan_Win32_SuspClickFix_Z_2147968174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Z"
        threat_id = "2147968174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 75 00 73 00 68 00 64 00 20 00 5c 00 5c 00 [0-96] 5c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {26 00 26 00 [0-32] 6f 00 64 00 62 00 63 00 63 00 6f 00 6e 00 66 00 20 00 [0-16] 66 00}  //weight: 1, accuracy: Low
        $x_2_3 = "conhost --headless odbcconf /f \\\\" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}
