rule VirTool_Win32_SuspPowershellCommand_B_2147768930_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowershellCommand.B"
        threat_id = "2147768930"
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
        $n_1_6 = "avoid_duplicate-{ab7ccefd-19b3-4b3f-b178-3e42a7077de9}" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
