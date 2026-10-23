rule VirTool_Win32_ExcludeProc_A_2147766901_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ExcludeProc.A"
        threat_id = "2147766901"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ExcludeProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = "Add-MpPreference -ExclusionProcess " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
