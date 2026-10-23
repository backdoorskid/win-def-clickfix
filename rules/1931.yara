rule Trojan_Win32_SusXmLTask_B_2147955628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusXmLTask.B"
        threat_id = "2147955628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusXmLTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c dir" ascii //weight: 1
        $x_1_2 = "mkdir" ascii //weight: 1
        $x_1_3 = "AppData\\Local" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
