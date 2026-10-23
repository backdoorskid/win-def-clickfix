rule VirTool_Win32_UACBypassExp_A_2147752130_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.A"
        threat_id = "2147752130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = "-MpPreference " wide //weight: 1
        $x_1_3 = " -DisableRealtimeMonitoring 1" wide //weight: 1
        $x_1_4 = " -ExclusionProcess" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
