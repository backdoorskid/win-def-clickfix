rule Trojan_Win32_SuspXmLTask_B_2147954175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspXmLTask.B"
        threat_id = "2147954175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspXmLTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c dir" ascii //weight: 1
        $x_1_2 = "mkdir" ascii //weight: 1
        $x_1_3 = "AppData\\Local" ascii //weight: 1
        $n_1_4 = "4b79ffab-a220-4ed5-a63d-1f1a9045113g" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
