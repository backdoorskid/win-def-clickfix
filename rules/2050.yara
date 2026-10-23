rule VirTool_Win32_ExcludeProc_B_2147772096_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ExcludeProc.B"
        threat_id = "2147772096"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ExcludeProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "Add-MpPreference -ExclusionPath $env:temp" wide //weight: 1
        $x_1_3 = "Add-MpPreference -ExclusionPath $env:appdata" wide //weight: 1
        $x_1_4 = "Net.WebClient).DownloadFile('http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
