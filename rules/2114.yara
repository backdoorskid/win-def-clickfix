rule VirTool_Win32_SuspPowershellCommand_D_2147769344_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowershellCommand.D"
        threat_id = "2147769344"
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
        $n_1_6 = "avoid_duplicate-{177c031f-02b2-4c18-8477-b069540f9c0c}" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
