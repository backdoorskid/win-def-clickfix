rule VirTool_Win32_SuspMsiExec_E_2147979668_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspMsiExec.E"
        threat_id = "2147979668"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMsiExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = {20 00 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {20 00 68 00 74 00 74 00 70 00 [0-2] 3a 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
