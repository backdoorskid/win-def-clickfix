rule VirTool_Win32_SuspServWmiCommand_F_2147767975_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspServWmiCommand.F"
        threat_id = "2147767975"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspServWmiCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = "Msiexec" wide //weight: 1
        $x_1_3 = " /i http" wide //weight: 1
        $x_1_4 = " /q" wide //weight: 1
        $n_100_5 = ".microsoft.com/" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
