rule VirTool_Win32_SuspPowershellCommand_C_2147768931_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowershellCommand.C"
        threat_id = "2147768931"
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
        $n_1_6 = "avoid_duplicate-{275ddc34-b64b-4166-9646-7900d446d9bd}" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
