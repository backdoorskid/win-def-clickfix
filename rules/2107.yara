rule VirTool_Win32_SuspObfusCmdExec_D_2147958109_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspObfusCmdExec.D"
        threat_id = "2147958109"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspObfusCmdExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = "powershell.exe" wide //weight: 1
        $x_1_4 = " win32_ComputerSystem" wide //weight: 1
        $x_10_5 = "G\"e\"t\"-\"Wmi\"O\"bje\"c\"t" wide //weight: 10
        $x_10_6 = "G\"e\"t\"-\"Wm^i\"O\"bje\"c\"t" wide //weight: 10
        $x_10_7 = " Get-Wm^iObject" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}
