rule VirTool_Win32_SuspClickFix_L_2147958625_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspClickFix.L"
        threat_id = "2147958625"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 75 00 72 00 6c 00 [0-8] 20 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = " | " wide //weight: 1
        $x_1_3 = "Invoke-Expression" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
