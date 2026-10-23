rule Trojan_Win32_SusProxy_G_2147954112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.G"
        threat_id = "2147954112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c copy" ascii //weight: 1
        $x_1_2 = "rundll32.exe" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "adobe.exe" ascii //weight: 1
        $n_1_5 = "a453e881-26a8-4973-bv2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}
