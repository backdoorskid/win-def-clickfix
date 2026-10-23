rule VirTool_Win32_SuspClickFix_P_2147959459_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspClickFix.P"
        threat_id = "2147959459"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wscript" wide //weight: 1
        $x_1_2 = " //E:VBScript" wide //weight: 1
        $x_1_3 = {20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 [0-64] 5c 00 [0-32] 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}
