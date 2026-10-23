rule Trojan_Win32_SuspXmLTask_A_2147954174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspXmLTask.A"
        threat_id = "2147954174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspXmLTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe" ascii //weight: 1
        $x_1_2 = "/create /TN" ascii //weight: 1
        $x_1_3 = "Events\\CacheTask_test" wide //weight: 1
        $x_1_4 = "/XML" ascii //weight: 1
        $x_1_5 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_6 = "events.xml" ascii //weight: 1
        $n_1_7 = "4b79ffab-a220-4ed5-a63d-1f1a9045113f" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
