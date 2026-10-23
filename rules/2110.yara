rule VirTool_Win32_SuspPowerShellCmd_BA_2147940318_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowerShellCmd.BA"
        threat_id = "2147940318"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowerShellCmd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe" ascii //weight: 1
        $x_1_2 = "-exec bypass -command " ascii //weight: 1
        $x_1_3 = "IO.FileStream '\\\\.\\C:'" ascii //weight: 1
        $x_1_4 = "'Open', 'Read', 'ReadWrite'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
