rule Trojan_Win32_SuspProxy_R_2147955575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.R"
        threat_id = "2147955575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "comDll.dll" ascii //weight: 1
        $x_1_4 = "startWorker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
