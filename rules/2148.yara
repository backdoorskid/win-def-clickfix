rule VirTool_Win32_SuspServWmiCommand_C_2147767972_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspServWmiCommand.C"
        threat_id = "2147767972"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspServWmiCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = "sv " wide //weight: 1
        $x_1_4 = ").value.toString()" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
