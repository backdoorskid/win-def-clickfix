rule VirTool_Win32_SuspPowershellCommand_A_2147768895_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowershellCommand.A"
        threat_id = "2147768895"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowershellCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "hidden" wide //weight: 1
        $x_1_3 = "-enc" wide //weight: 1
        $n_100_4 = "CgAkAFMAYwByAGkAcAB0ACAAPQAgAHsAbgBlAHQAcwB0AGEAdAAuAGUAeABlACAALQBhAG4AIAAt" wide //weight: -100
        $n_100_5 = " -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -NoProfile -EncodedCommand " wide //weight: -100
        $n_100_6 = "@{}; $List = New-Object System.Collections.Generic.List[System.Object];Get-ChildItem 'HKLM:\\SOFTWARE\\" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
