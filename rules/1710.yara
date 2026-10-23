rule Trojan_Win32_SuspProxy_G_2147954132_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.G"
        threat_id = "2147954132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c copy" ascii //weight: 1
        $x_1_2 = "rundll32.exe" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "adobe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}
