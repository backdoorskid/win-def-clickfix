rule Trojan_Win32_SusXmLTask_C_2147955629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusXmLTask.C"
        threat_id = "2147955629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusXmLTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe /create" ascii //weight: 1
        $x_1_2 = "/sc minute /mo" ascii //weight: 1
        $x_1_3 = "AppData\\Local" ascii //weight: 1
        $x_1_4 = "Maintenance" ascii //weight: 1
        $x_1_5 = "/tn" wide //weight: 1
        $x_1_6 = ".vbs" wide //weight: 1
        $x_1_7 = "/tr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
