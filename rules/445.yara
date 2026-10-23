rule Backdoor_Win32_CobaltStrikeLoader_CM_2147793650_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrikeLoader.CM!dha"
        threat_id = "2147793650"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "rundll32.exe" wide //weight: 5
        $x_5_2 = "11985" wide //weight: 5
        $x_1_3 = "ClearMyTracksByProcess" wide //weight: 1
        $x_1_4 = "AllocConsole" wide //weight: 1
        $n_100_5 = "inetcpl.cpl" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
