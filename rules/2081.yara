rule VirTool_Win32_SuspClickFix_M_2147954202_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspClickFix.M"
        threat_id = "2147954202"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http" wide //weight: 5
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = "msiexec" wide //weight: 1
        $x_1_4 = "mshta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
