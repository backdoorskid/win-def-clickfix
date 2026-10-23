rule VirTool_Win32_ExcludeProc_E_2147846527_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ExcludeProc.E"
        threat_id = "2147846527"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ExcludeProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = " -c" wide //weight: 1
        $x_1_5 = "-MpPreference -ExclusionPath " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
