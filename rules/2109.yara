rule VirTool_Win32_SuspPowerShellCmd_BL_2147939802_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowerShellCmd.BL"
        threat_id = "2147939802"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowerShellCmd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "& c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe" ascii //weight: 3
        $x_3_2 = "-exec bypass -command " ascii //weight: 3
        $x_3_3 = "set-psreadlineoption" ascii //weight: 3
        $x_1_4 = "-historysavestyle savenothing" ascii //weight: 1
        $x_1_5 = "-historysavepath ${temp}/" ascii //weight: 1
        $x_1_6 = "-maximumhistorycount 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
