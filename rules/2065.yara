rule VirTool_Win32_Magniber_B_2147846013_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.B"
        threat_id = "2147846013"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = {73 00 65 00 74 00 20 00 [0-8] 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {20 00 26 00 26 00 20 00 63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 65 00 63 00 68 00 6f 00 20 00 25 00 [0-8] 3a 00 7e 00 [0-8] 2c 00 [0-8] 25 00 25 00 [0-8] 3a 00 7e 00 [0-8] 2c 00 [0-8] 25 00 25 00 [0-8] 3a 00 7e 00 [0-8] 2c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "% | powershell -" wide //weight: 1
        $x_1_5 = {25 00 20 00 7c 00 20 00 63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 25 00 [0-8] 3a 00 7e 00 [0-8] 2c 00 [0-8] 25 00 25 00 [0-8] 3a 00 7e 00 [0-8] 2c 00 [0-8] 25 00 25 00 [0-8] 3a 00 7e 00 [0-8] 2c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}
