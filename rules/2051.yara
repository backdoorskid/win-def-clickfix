rule VirTool_Win32_ExcludeProc_C_2147797730_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ExcludeProc.C"
        threat_id = "2147797730"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ExcludeProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_2_2 = "Add-MpPreference -ExclusionExtension @('exe','dll')" wide //weight: 2
        $x_1_3 = "Add-MpPreference -ExclusionPath @(($pwd).path," wide //weight: 1
        $x_1_4 = "Add-MpPreference -ExclusionPath @($env:UserProfile," wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
