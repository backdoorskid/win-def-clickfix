rule VirTool_Win32_SuspPowershellCommand_E_2147769831_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowershellCommand.E"
        threat_id = "2147769831"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowershellCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "-enc" wide //weight: 1
        $n_100_3 = "CgAkAFMAYwByAGkAcAB0ACAAPQAgAHsAbgBlAHQAcwB0AGEAdAAuAGUAeABlACAALQBhAG4AIAAt" wide //weight: -100
        $n_100_4 = " -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -NoProfile -EncodedCommand " wide //weight: -100
        $n_1_5 = "avoid_duplicate-{24d6a156-033d-43fe-9d51-a993a06cc816}" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
