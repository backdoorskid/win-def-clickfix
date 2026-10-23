rule Trojan_Win32_SuspProxy_H_2147954133_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.H"
        threat_id = "2147954133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "url,OpenURL file:" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "adobe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
