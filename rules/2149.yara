rule VirTool_Win32_SuspServWmiCommand_D_2147767973_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspServWmiCommand.D"
        threat_id = "2147767973"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspServWmiCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = ").DownloadFile(" wide //weight: 1
        $x_1_4 = "::ReadAllBytes(" wide //weight: 1
        $x_1_5 = "::WriteAllBytes(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
